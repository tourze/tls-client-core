<?php

declare(strict_types=1);

namespace Tourze\TLSClientCore;

use Tourze\TLSCommon\Exception\ProtocolException;
use Tourze\TLSCommon\Exception\TLSException;
use Tourze\TLSHandshakeFlow\StateMachine\HandshakeStateEnum;
use Tourze\TLSHandshakeFlow\StateMachine\HandshakeStateMachineInterface;
use Tourze\TLSHandshakeMessages\Protocol\HandshakeMessageType;

/**
 * TLS客户端状态机
 */
final class ClientStateMachine implements HandshakeStateMachineInterface
{
    private ClientStateEnum $currentState;

    private bool $errorState = false;

    public function __construct()
    {
        $this->currentState = ClientStateEnum::INITIAL;
    }

    public function getCurrentState(): HandshakeStateEnum
    {
        return $this->mapToHandshakeState($this->currentState);
    }

    /**
     * 将客户端状态映射到握手状态
     */
    private function mapToHandshakeState(ClientStateEnum $clientState): HandshakeStateEnum
    {
        return match ($clientState) {
            ClientStateEnum::INITIAL => HandshakeStateEnum::INITIAL,
            ClientStateEnum::WAIT_SERVER_HELLO => HandshakeStateEnum::WAIT_SERVER_HELLO,
            ClientStateEnum::WAIT_ENCRYPTED_EXTENSIONS => HandshakeStateEnum::WAIT_ENCRYPTED_EXTENSIONS,
            ClientStateEnum::WAIT_CERTIFICATE => HandshakeStateEnum::WAIT_CERTIFICATE,
            ClientStateEnum::WAIT_CERTIFICATE_VERIFY => HandshakeStateEnum::WAIT_CERTIFICATE_VERIFY,
            ClientStateEnum::WAIT_FINISHED => HandshakeStateEnum::WAIT_FINISHED,
            ClientStateEnum::CONNECTED => HandshakeStateEnum::CONNECTED,
            ClientStateEnum::ERROR => HandshakeStateEnum::ERROR,
        };
    }

    public function getCurrentClientState(): ClientStateEnum
    {
        return $this->currentState;
    }

    public function transitionTo(HandshakeStateEnum $state): void
    {
        $newState = $this->mapToClientState($state);

        if (null === $newState) {
            $this->errorState = true;
            throw new ProtocolException("Invalid state transition to: {$state->value}");
        }

        if (!$this->isValidTransition($this->currentState, $newState)) {
            $this->errorState = true;
            throw new ProtocolException("Invalid state transition from {$this->currentState->value} to {$newState->value}");
        }

        $this->currentState = $newState;
    }

    /**
     * 将握手状态映射到客户端状态
     */
    private function mapToClientState(HandshakeStateEnum $handshakeState): ?ClientStateEnum
    {
        return match ($handshakeState) {
            HandshakeStateEnum::INITIAL => ClientStateEnum::INITIAL,
            HandshakeStateEnum::WAIT_SERVER_HELLO => ClientStateEnum::WAIT_SERVER_HELLO,
            HandshakeStateEnum::WAIT_ENCRYPTED_EXTENSIONS => ClientStateEnum::WAIT_ENCRYPTED_EXTENSIONS,
            HandshakeStateEnum::WAIT_CERTIFICATE => ClientStateEnum::WAIT_CERTIFICATE,
            HandshakeStateEnum::WAIT_CERTIFICATE_VERIFY => ClientStateEnum::WAIT_CERTIFICATE_VERIFY,
            HandshakeStateEnum::WAIT_FINISHED => ClientStateEnum::WAIT_FINISHED,
            HandshakeStateEnum::CONNECTED => ClientStateEnum::CONNECTED,
            HandshakeStateEnum::ERROR => ClientStateEnum::ERROR,
            default => null,
        };
    }

    /**
     * 检查状态转换是否有效
     */
    private function isValidTransition(ClientStateEnum $from, ClientStateEnum $to): bool
    {
        $validTransitions = [
            ClientStateEnum::INITIAL->value => [
                ClientStateEnum::WAIT_SERVER_HELLO->value,
                ClientStateEnum::ERROR->value,
            ],
            ClientStateEnum::WAIT_SERVER_HELLO->value => [
                ClientStateEnum::WAIT_ENCRYPTED_EXTENSIONS->value,
                ClientStateEnum::ERROR->value,
            ],
            ClientStateEnum::WAIT_ENCRYPTED_EXTENSIONS->value => [
                ClientStateEnum::WAIT_CERTIFICATE->value,
                ClientStateEnum::ERROR->value,
            ],
            ClientStateEnum::WAIT_CERTIFICATE->value => [
                ClientStateEnum::WAIT_CERTIFICATE_VERIFY->value,
                ClientStateEnum::ERROR->value,
            ],
            ClientStateEnum::WAIT_CERTIFICATE_VERIFY->value => [
                ClientStateEnum::WAIT_FINISHED->value,
                ClientStateEnum::ERROR->value,
            ],
            ClientStateEnum::WAIT_FINISHED->value => [
                ClientStateEnum::CONNECTED->value,
                ClientStateEnum::ERROR->value,
            ],
            ClientStateEnum::CONNECTED->value => [
                ClientStateEnum::ERROR->value,
            ],
            ClientStateEnum::ERROR->value => [],
        ];

        return in_array($to->value, $validTransitions[$from->value] ?? [], true);
    }

    public function transitionToString(string $state): void
    {
        $newState = ClientStateEnum::tryFrom($state);

        if (null === $newState) {
            $this->errorState = true;
            throw new ProtocolException("Invalid state transition to: {$state}");
        }

        if (!$this->isValidTransition($this->currentState, $newState)) {
            $this->errorState = true;
            throw new ProtocolException("Invalid state transition from {$this->currentState->value} to {$newState->value}");
        }

        $this->currentState = $newState;
    }

    public function getNextState(HandshakeMessageType $messageType): HandshakeStateEnum
    {
        $nextClientState = match ($this->currentState) {
            ClientStateEnum::INITIAL => ClientStateEnum::WAIT_SERVER_HELLO,
            ClientStateEnum::WAIT_SERVER_HELLO => ClientStateEnum::WAIT_ENCRYPTED_EXTENSIONS,
            ClientStateEnum::WAIT_ENCRYPTED_EXTENSIONS => ClientStateEnum::WAIT_CERTIFICATE,
            ClientStateEnum::WAIT_CERTIFICATE => ClientStateEnum::WAIT_CERTIFICATE_VERIFY,
            ClientStateEnum::WAIT_CERTIFICATE_VERIFY => ClientStateEnum::WAIT_FINISHED,
            ClientStateEnum::WAIT_FINISHED => ClientStateEnum::CONNECTED,
            ClientStateEnum::CONNECTED => ClientStateEnum::CONNECTED,
            ClientStateEnum::ERROR => ClientStateEnum::ERROR,
        };

        return $this->mapToHandshakeState($nextClientState);
    }

    public function getNextClientState(): ?ClientStateEnum
    {
        return match ($this->currentState) {
            ClientStateEnum::INITIAL => ClientStateEnum::WAIT_SERVER_HELLO,
            ClientStateEnum::WAIT_SERVER_HELLO => ClientStateEnum::WAIT_ENCRYPTED_EXTENSIONS,
            ClientStateEnum::WAIT_ENCRYPTED_EXTENSIONS => ClientStateEnum::WAIT_CERTIFICATE,
            ClientStateEnum::WAIT_CERTIFICATE => ClientStateEnum::WAIT_CERTIFICATE_VERIFY,
            ClientStateEnum::WAIT_CERTIFICATE_VERIFY => ClientStateEnum::WAIT_FINISHED,
            ClientStateEnum::WAIT_FINISHED => ClientStateEnum::CONNECTED,
            ClientStateEnum::CONNECTED => null,
            ClientStateEnum::ERROR => null,
        };
    }

    public function isInErrorState(): bool
    {
        return $this->errorState || ClientStateEnum::ERROR === $this->currentState;
    }

    public function isHandshakeCompleted(): bool
    {
        return ClientStateEnum::CONNECTED === $this->currentState;
    }

    public function reset(): void
    {
        $this->currentState = ClientStateEnum::INITIAL;
        $this->errorState = false;
    }

    /**
     * 获取当前状态的描述
     */
    public function getCurrentStateDescription(): string
    {
        return match ($this->currentState) {
            ClientStateEnum::INITIAL => 'Initial state, ready to start handshake',
            ClientStateEnum::WAIT_SERVER_HELLO => 'Waiting for ServerHello message',
            ClientStateEnum::WAIT_ENCRYPTED_EXTENSIONS => 'Waiting for EncryptedExtensions message',
            ClientStateEnum::WAIT_CERTIFICATE => 'Waiting for Certificate message',
            ClientStateEnum::WAIT_CERTIFICATE_VERIFY => 'Waiting for CertificateVerify message',
            ClientStateEnum::WAIT_FINISHED => 'Waiting for Finished message',
            ClientStateEnum::CONNECTED => 'Handshake completed, connection established',
            ClientStateEnum::ERROR => 'Error state, connection failed',
        };
    }

    /**
     * 是否可以发送应用数据
     */
    public function canSendApplicationData(): bool
    {
        return ClientStateEnum::CONNECTED === $this->currentState;
    }

    /**
     * 是否可以接收应用数据
     */
    public function canReceiveApplicationData(): bool
    {
        return ClientStateEnum::CONNECTED === $this->currentState;
    }
}
