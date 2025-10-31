<?php

declare(strict_types=1);

namespace Tourze\TLSClientCore;

use Tourze\TLSClientCore\Crypto\TLSKeyManager;
use Tourze\TLSClientCore\Protocol\HandshakeMessageProcessor;
use Tourze\TLSCommon\Exception\ProtocolException;
use Tourze\TLSCommon\Exception\TLSException;
use Tourze\TLSCommon\Protocol\TLSVersion;
use Tourze\TLSExtensionNaming\Extension\ALPNExtension;
use Tourze\TLSExtensionNaming\Extension\ExtensionType as NamingExtensionType;
use Tourze\TLSExtensionNaming\Extension\ServerNameExtension;
use Tourze\TLSExtensionNaming\Extension\SignatureAlgorithmsExtension;
use Tourze\TLSExtensionNaming\Extension\SupportedVersionsExtension;
use Tourze\TLSExtensionSecure\Extension\SupportedGroupsExtension as SecureSupportedGroupsExtension;
use Tourze\TLSExtensionTLS13\Extension\KeyShareEntry;
use Tourze\TLSExtensionTLS13\Extension\KeyShareExtension;
use Tourze\TLSExtensionTLS13\Extension\PSKKeyExchangeModesExtension;
use Tourze\TLSHandshakeMessages\Message\ClientHelloMessage;
use Tourze\TLSHandshakeMessages\Message\FinishedMessage;
use Tourze\TLSRecord\CipherState;
use Tourze\TLSRecord\Exception\RecordException;
use Tourze\TLSRecord\RecordLayer;
use Tourze\TLSRecord\RecordProtocol;
use Tourze\TLSRecord\Transport\SocketTransport;

/**
 * TLS客户端连接管理器
 */
final class ClientConnectionManager
{
    private ?RecordProtocol $recordProtocol = null;

    private bool $connected = false;

    /** @var array<string> */
    private array $cipherSuites = [];

    private string $handshakeTranscript = '';

    private string $selectedCipherSuite = 'TLS_AES_128_GCM_SHA256';

    private string $handshakeRecvBuffer = '';

    private TLSKeyManager $keyManager;

    private HandshakeMessageProcessor $messageProcessor;

    /**
     * @param array<string, mixed> $options
     */
    public function __construct(
        private readonly string $hostname,
        private readonly int $port = 443,
        private readonly array $options = [],
    ) {
        $this->initializeOptions();
        $this->keyManager = new TLSKeyManager();
        $this->messageProcessor = new HandshakeMessageProcessor($this->cipherSuites);
    }

    private function initializeOptions(): void
    {
        $configured = $this->options['cipher_suites'] ?? ['TLS_AES_128_GCM_SHA256'];
        $defaults = ['TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256'];

        foreach ($defaults as $suite) {
            if (!in_array($suite, $configured, true)) {
                $configured[] = $suite;
            }
        }

        $this->cipherSuites = $configured;
    }

    public function __destruct()
    {
        $this->close();
    }

    /**
     * 关闭连接
     */
    public function close(): void
    {
        if (null !== $this->recordProtocol) {
            // RecordProtocol 内部会处理传输层关闭
        }

        $this->recordProtocol = null;
        $this->connected = false;
    }

    /**
     * 建立底层连接
     */
    public function establishConnection(): void
    {
        if ($this->connected) {
            return;
        }

        try {
            $transport = new SocketTransport($this->hostname, $this->port, $this->options['timeout'] ?? 30);
            $this->recordProtocol = new RecordLayer($transport, TLSVersion::TLS_1_3->value);
            $this->connected = true;
        } catch (\Exception $e) {
            throw new ProtocolException("Failed to connect to {$this->hostname}:{$this->port}: {$e->getMessage()}", 0, $e);
        }
    }

    /**
     * 发送ClientHello消息
     */
    public function sendClientHello(): void
    {
        $this->ensureConnected();

        $this->keyManager->generateClientKeyPair();

        // 构建 SNI / supported_versions / signature_algorithms / key_share 扩展
        $exts = [];
        $sni = new ServerNameExtension([$this->hostname]);
        $exts[NamingExtensionType::SERVER_NAME->value] = $sni->encode();
        // 仅宣告 TLS 1.3，避免服务器回落到 1.2 导致密码套件不匹配
        $sv = new SupportedVersionsExtension([SupportedVersionsExtension::TLS_1_3]);
        $exts[NamingExtensionType::SUPPORTED_VERSIONS->value] = $sv->encode();
        // supported_groups: 推荐 X25519 + P-256 + P-384
        $sg = new SecureSupportedGroupsExtension();
        $sg->setGroups([0x001D, 0x0017, 0x0018]);
        $exts[NamingExtensionType::SUPPORTED_GROUPS->value] = $sg->encode();
        $sig = new SignatureAlgorithmsExtension([
            SignatureAlgorithmsExtension::RSA_PSS_RSAE_SHA256,
            SignatureAlgorithmsExtension::ECDSA_SECP256R1_SHA256,
            SignatureAlgorithmsExtension::RSA_PKCS1_SHA256,
        ]);
        $exts[NamingExtensionType::SIGNATURE_ALGORITHMS->value] = $sig->encode();
        // 不发送 renegotiation_info（TLS 1.3 不再重协商，且部分服务端看到该扩展会直接关闭）
        // psk_key_exchange_modes: 明确仅支持 psk_dhe_ke
        $pskModes = new PSKKeyExchangeModesExtension([PSKKeyExchangeModesExtension::PSK_DHE_KE]);
        $exts[NamingExtensionType::PSK_KEY_EXCHANGE_MODES->value] = $pskModes->encode();
        $ks = new KeyShareExtension(false);
        $entry = new KeyShareEntry();
        $entry->setGroup(0x001D);
        $entry->setKeyExchange($this->keyManager->getClientPublicKey() ?? '');
        $ks->addEntry($entry);
        $exts[NamingExtensionType::KEY_SHARE->value] = $ks->encode();

        $clientHello = new ClientHelloMessage();
        // TLS 1.3 的 ClientHello.legacy_version 必须为 0x0303（TLS1.2）
        // 为兼容某些中间盒，legacy_session_id 建议非空，这里使用 32 字节随机值
        $alpn = new ALPNExtension([
            ALPNExtension::PROTOCOL_HTTP_1_1,
        ]);
        $exts[NamingExtensionType::ALPN->value] = $alpn->encode();

        $clientHello->setVersion(0x0303);
        $clientHello->setRandom($this->generateClientRandom());
        $clientHello->setSessionId(random_bytes(32));
        $clientHello->setCipherSuites($this->messageProcessor->convertCipherSuitesToInts($this->cipherSuites));
        $clientHello->setCompressionMethods([0]);
        $clientHello->setExtensions($exts);

        if (null === $this->recordProtocol) {
            throw new ProtocolException('Connection not established');
        }
        $encoded = $clientHello->encode();
        $this->handshakeTranscript .= $encoded;
        $this->recordProtocol->sendRecord(22, $encoded);
        // 发送保持连接活跃的小延时，避免某些服务端在握手间隙立即超时关闭
        usleep(30000);
        // 兼容模式：发送一个虚假的 ChangeCipherSpec 以兼容某些中间盒/服务端实现
        // 参考 RFC 8446 Appendix D.4
        $this->recordProtocol->sendRecord(20, "\x01");
    }

    /**
     * 确保连接已建立
     */
    private function ensureConnected(): void
    {
        if (!$this->isConnected()) {
            throw new ProtocolException('Connection not established');
        }
    }

    /**
     * 获取连接状态
     */
    public function isConnected(): bool
    {
        return $this->connected && null !== $this->recordProtocol;
    }

    /**
     * 生成客户端随机数
     */
    private function generateClientRandom(): string
    {
        return random_bytes(32);
    }

    /**
     * 接收消息
     */
    public function receiveMessage(): string
    {
        $this->ensureConnected();

        if (null === $this->recordProtocol) {
            throw new ProtocolException('Connection not established');
        }

        // 尝试从缓冲区拆出完整的握手消息
        $msg = $this->tryExtractHandshakeFromBuffer();
        if (null !== $msg) {
            return $msg;
        }

        // 循环读取记录，直到拼出完整的握手消息
        while (true) {
            $record = $this->recordProtocol->receiveRecord();
            // 仅处理握手类型，忽略 TLS 1.3 兼容性的明文 CCS 记录
            if (22 /* handshake */ !== $record->getContentType()) {
                continue;
            }
            $this->handshakeRecvBuffer .= $record->getData();

            $msg = $this->tryExtractHandshakeFromBuffer();
            if (null !== $msg) {
                return $msg;
            }
        }
    }

    /**
     * 从缓冲区尝试解析一条完整握手消息（type[1] + len[3] + body[len]）。
     */
    private function tryExtractHandshakeFromBuffer(): ?string
    {
        $bufLen = strlen($this->handshakeRecvBuffer);
        if ($bufLen < 4) {
            return null;
        }
        $type = ord($this->handshakeRecvBuffer[0]);
        $len = ((ord($this->handshakeRecvBuffer[1]) << 16) | (ord($this->handshakeRecvBuffer[2]) << 8) | ord($this->handshakeRecvBuffer[3]));
        $total = 4 + $len;
        if ($bufLen < $total) {
            return null;
        }
        $msg = substr($this->handshakeRecvBuffer, 0, $total);
        $this->handshakeRecvBuffer = substr($this->handshakeRecvBuffer, $total);

        return $msg;
    }

    public function processServerHello(string $message): void
    {
        $this->handshakeTranscript .= $message;
        $this->selectedCipherSuite = $this->messageProcessor->processServerHello($message, $this->keyManager);

        $this->keyManager->computeSharedSecret();
        $this->keyManager->deriveHandshakeSecrets($this->handshakeTranscript);

        $cipherStates = $this->keyManager->createHandshakeCipherStates($this->selectedCipherSuite);
        $this->updateRecordProtocolCipherSpec($cipherStates);
    }

    public function processEncryptedExtensions(string $message): void
    {
        $this->handshakeTranscript .= $message;
        $this->messageProcessor->processEncryptedExtensions($message);
    }

    public function processCertificate(string $message): void
    {
        $this->handshakeTranscript .= $message;
        $this->messageProcessor->processCertificate($message);
    }

    public function processCertificateVerify(string $message): void
    {
        $this->handshakeTranscript .= $message;
        $this->messageProcessor->processCertificateVerify($message);
    }

    public function processServerFinished(string $message): void
    {
        $this->messageProcessor->processServerFinished($message, $this->handshakeTranscript, $this->keyManager);
        $this->handshakeTranscript .= $message;
    }

    /**
     * 发送ClientFinished消息
     */
    public function sendClientFinished(): void
    {
        $this->ensureConnected();

        if (null === $this->recordProtocol) {
            throw new ProtocolException('Connection not established');
        }

        $verifyData = $this->keyManager->createFinishedVerifyData($this->handshakeTranscript, true);

        $fm = new FinishedMessage();
        $fm->setVerifyData($verifyData);
        $finishedMessage = $fm->encode();
        $this->recordProtocol->sendRecord(22, $finishedMessage);

        $this->handshakeTranscript .= $finishedMessage;

        $this->keyManager->deriveApplicationSecrets($this->handshakeTranscript);
        $appCipherStates = $this->keyManager->createApplicationCipherStates($this->selectedCipherSuite);
        $this->updateRecordProtocolCipherSpec($appCipherStates);
    }

    /**
     * 处理应用数据
     */
    public function processApplicationData(string $data): string
    {
        $this->sendApplicationData($data);

        return $this->receiveApplicationData();
    }

    /**
     * 发送应用数据
     */
    public function sendApplicationData(string $data): void
    {
        $this->ensureConnected();
        if (null === $this->recordProtocol) {
            throw new ProtocolException('Connection not established');
        }
        $this->recordProtocol->sendRecord(23, $data);
    }

    /**
     * 接收应用数据
     */
    public function receiveApplicationData(): string
    {
        $this->ensureConnected();

        if (null === $this->recordProtocol) {
            throw new ProtocolException('Connection not established');
        }
        // 连续读取 application_data 记录，解密后根据原始内容类型分支：
        // - originalContentType == application_data -> 返回明文
        // - originalContentType == handshake (如 NewSessionTicket) -> 跳过，继续读
        while (true) {
            try {
                $record = $this->recordProtocol->receiveRecord();
            } catch (RecordException $e) {
                // 对无法验证的记录直接跳过，继续读取下一条（常见于中间盒或多余的 ticket）
                if (\defined('STDERR')) {
                    @fwrite(STDERR, '[TLS] Skip invalid record: ' . $e->getMessage() . "\n");
                }
                continue;
            }
            if (23 !== $record->getContentType()) {
                // 跳过非 application_data（例如 明文 CCS）
                continue;
            }

            // 记录层在 TLS 1.3 下会把解密后的 originalContentType 写回 RecordData.contentType
            // 因为前面已经过滤了非 application_data 记录，这里直接返回解密后的明文
            return $record->getData();
        }
    }

    /**
     * 获取主机名
     */
    public function getHostname(): string
    {
        return $this->hostname;
    }

    /**
     * 获取端口
     */
    public function getPort(): int
    {
        return $this->port;
    }

    /**
     * 获取选项
     * @return array<string, mixed>
     */
    public function getOptions(): array
    {
        return $this->options;
    }

    /**
     * @param array<string, CipherState> $cipherStates
     */
    private function updateRecordProtocolCipherSpec(array $cipherStates): void
    {
        if (null === $this->recordProtocol) {
            throw new ProtocolException('Connection not established');
        }

        $this->recordProtocol->changeWriteCipherSpec($cipherStates['client']);
        $this->recordProtocol->changeReadCipherSpec($cipherStates['server']);
    }
}
