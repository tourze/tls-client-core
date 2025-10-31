<?php

declare(strict_types=1);

namespace Tourze\TLSClientCore;

use Tourze\TLSCommon\Exception\ProtocolException;
use Tourze\TLSCommon\Exception\TLSException;
use Tourze\TLSCommon\Protocol\TLSProtocolInterface;

/**
 * TLS客户端核心实现
 */
final class TLSClientCore implements TLSProtocolInterface
{
    private ClientConnectionManager $connectionManager;

    private ClientStateMachine $stateMachine;

    private bool $established = false;

    private string $state = 'initial';

    private bool $useNative = false;

    private ?NativeTLSClient $nativeClient = null;

    /**
     * @param array<string, mixed> $options
     */
    public function __construct(
        string $hostname,
        int $port = 443,
        private readonly array $options = [],
    ) {
        $this->connectionManager = new ClientConnectionManager($hostname, $port, $options);
        $this->stateMachine = new ClientStateMachine();
        $this->useNative = (bool) ($options['use_native'] ?? false);
        if ($this->useNative) {
            $this->nativeClient = new NativeTLSClient($hostname, $port, $options);
        }
    }

    public function getName(): string
    {
        return 'TLS Client';
    }

    public function getVersion(): int
    {
        $version = $this->options['version'] ?? '1.3';

        return match ($version) {
            '1.0' => 10,
            '1.1' => 11,
            '1.2' => 12,
            '1.3' => 13,
            default => 13,
        };
    }

    public function process(string $data): string
    {
        if (!$this->established) {
            throw new ProtocolException('TLS connection not established');
        }

        return $this->connectionManager->processApplicationData($data);
    }

    public function isEstablished(): bool
    {
        return $this->established;
    }

    public function getState(): string
    {
        return $this->state;
    }

    public function close(): void
    {
        if ($this->useNative) {
            $this->nativeClient?->close();
        } else {
            $this->connectionManager->close();
        }
        $this->established = false;
        $this->state = 'closed';
    }

    /**
     * 建立TLS连接
     */
    public function connect(): void
    {
        $this->state = 'connecting';

        try {
            if ($this->useNative) {
                $this->nativeClient?->connect();
                $this->established = true;
                $this->state = 'established';
            } else {
                $this->connectionManager->establishConnection();
                $this->performHandshake();

                $this->established = true;
                $this->state = 'established';
            }
        } catch (\Exception $e) {
            $this->state = 'error';
            throw new ProtocolException('Failed to establish TLS connection: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * 执行TLS握手
     */
    private function performHandshake(): void
    {
        $this->stateMachine->reset();

        while (!$this->stateMachine->isHandshakeCompleted()) {
            $this->processHandshakeStep();
        }
    }

    /**
     * 处理握手步骤
     */
    private function processHandshakeStep(): void
    {
        $currentState = $this->stateMachine->getCurrentState();

        $clientState = $this->stateMachine->getCurrentClientState();

        switch ($clientState->value) {
            case 'initial':
                $this->sendClientHello();
                break;
            case 'wait_server_hello':
                $this->processServerHello();
                break;
            case 'wait_encrypted_extensions':
                $this->processEncryptedExtensions();
                break;
            case 'wait_certificate':
                $this->processCertificate();
                break;
            case 'wait_certificate_verify':
                $this->processCertificateVerify();
                break;
            case 'wait_finished':
                $this->processServerFinished();
                break;
            default:
                throw new ProtocolException('Unknown handshake state: ' . $clientState->value);
        }
    }

    private function sendClientHello(): void
    {
        $this->connectionManager->sendClientHello();
        $this->stateMachine->transitionToString('wait_server_hello');
    }

    private function processServerHello(): void
    {
        $message = $this->connectionManager->receiveMessage();
        $this->connectionManager->processServerHello($message);
        $this->stateMachine->transitionToString('wait_encrypted_extensions');
    }

    private function processEncryptedExtensions(): void
    {
        $message = $this->connectionManager->receiveMessage();
        $this->connectionManager->processEncryptedExtensions($message);
        $this->stateMachine->transitionToString('wait_certificate');
    }

    private function processCertificate(): void
    {
        $message = $this->connectionManager->receiveMessage();
        $this->connectionManager->processCertificate($message);
        $this->stateMachine->transitionToString('wait_certificate_verify');
    }

    private function processCertificateVerify(): void
    {
        $message = $this->connectionManager->receiveMessage();
        $this->connectionManager->processCertificateVerify($message);
        $this->stateMachine->transitionToString('wait_finished');
    }

    private function processServerFinished(): void
    {
        $message = $this->connectionManager->receiveMessage();
        $this->connectionManager->processServerFinished($message);

        $this->connectionManager->sendClientFinished();
        $this->stateMachine->transitionToString('connected');
    }

    /**
     * 获取连接管理器
     */
    public function getConnectionManager(): ClientConnectionManager
    {
        return $this->connectionManager;
    }

    /**
     * 获取状态机
     */
    public function getStateMachine(): ClientStateMachine
    {
        return $this->stateMachine;
    }

    /**
     * 发送应用数据
     */
    public function sendData(string $data): void
    {
        if (!$this->established) {
            throw new ProtocolException('Connection not established');
        }
        if ($this->useNative) {
            $this->nativeClient?->send($data);
        } else {
            $this->connectionManager->sendApplicationData($data);
        }
    }

    /**
     * 接收应用数据
     */
    public function receiveData(): string
    {
        if (!$this->established) {
            throw new ProtocolException('Connection not established');
        }
        if ($this->useNative) {
            // 读取最多 16KB，足够获取HTTP头与部分主体
            return $this->nativeClient?->receive(16384) ?? '';
        }

        return $this->connectionManager->receiveApplicationData();
    }

    /**
     * 获取底层原生 TLS 的加密信息元数据（仅 use_native 模式有效）
     *
     * @return array<string,mixed>
     */
    public function getNativeCryptoMeta(): array
    {
        if (!$this->useNative) {
            return [];
        }

        return $this->nativeClient?->getCryptoMeta() ?? [];
    }
}
