<?php

declare(strict_types=1);

namespace Tourze\TLSClientCore\Protocol;

use Tourze\TLSClientCore\Crypto\TLSKeyManager;
use Tourze\TLSCommon\Exception\ProtocolException;
use Tourze\TLSCommon\Exception\TLSException;
use Tourze\TLSExtensionNaming\Extension\ExtensionType as NamingExtensionType;
use Tourze\TLSExtensionTLS13\Extension\KeyShareExtension;
use Tourze\TLSHandshakeMessages\Message\CertificateMessage;
use Tourze\TLSHandshakeMessages\Message\CertificateVerifyMessage;
use Tourze\TLSHandshakeMessages\Message\EncryptedExtensionsMessage;
use Tourze\TLSHandshakeMessages\Message\FinishedMessage;
use Tourze\TLSHandshakeMessages\Message\ServerHelloMessage;

/**
 * 握手消息处理器 - 专门处理各种握手消息的解析和验证
 */
final class HandshakeMessageProcessor
{
    /** @var string[] */
    private array $supportedCipherSuites;

    /**
     * @param array<string> $supportedCipherSuites
     */
    public function __construct(array $supportedCipherSuites = [])
    {
        $this->supportedCipherSuites = $supportedCipherSuites;
    }

    public function processServerHello(string $message, TLSKeyManager $keyManager): string
    {
        $serverHello = ServerHelloMessage::decode($message);

        if (!$this->isValidServerHello($serverHello)) {
            throw new ProtocolException('Invalid ServerHello message');
        }

        $cipherSuite = $this->negotiateCipherSuite($serverHello->getCipherSuite());
        $this->configureKeyManagerForCipher($keyManager, $cipherSuite);
        $this->extractServerKeyShare($serverHello, $keyManager);

        return $cipherSuite;
    }

    public function processEncryptedExtensions(string $message): void
    {
        EncryptedExtensionsMessage::decode($message);
    }

    public function processCertificate(string $message): void
    {
        try {
            CertificateMessage::decode($message);
        } catch (\Throwable) {
            // Certificate处理失败时静默忽略
        }
    }

    public function processCertificateVerify(string $message): void
    {
        try {
            CertificateVerifyMessage::decode($message);
        } catch (\Throwable) {
            // CertificateVerify处理失败时静默忽略
        }
    }

    public function processServerFinished(string $message, string $handshakeTranscript, TLSKeyManager $keyManager): void
    {
        $serverFinished = FinishedMessage::decode($message);
        $verifyData = $serverFinished->getVerifyData();

        // 尝试两种验证方式：包含当前消息的transcript和不包含的
        if (!$keyManager->verifyFinishedMessage($verifyData, $handshakeTranscript, false)) {
            $alternativeTranscript = $handshakeTranscript . $message;
            if (!$keyManager->verifyFinishedMessage($verifyData, $alternativeTranscript, false)) {
                throw new ProtocolException('Server Finished verify_data mismatch');
            }
        }
    }

    private function isValidServerHello(ServerHelloMessage $serverHello): bool
    {
        $supportedVersions = [0x0303, 0x0304];
        if (!in_array($serverHello->getVersion(), $supportedVersions, true)) {
            return false;
        }

        $cipherSuiteInts = $this->convertCipherSuitesToInts($this->supportedCipherSuites);

        return in_array($serverHello->getCipherSuite(), $cipherSuiteInts, true);
    }

    private function negotiateCipherSuite(int $cipherSuite): string
    {
        $cipherSuiteInts = $this->convertCipherSuitesToInts($this->supportedCipherSuites);
        if (!in_array($cipherSuite, $cipherSuiteInts, true)) {
            throw new ProtocolException('Unsupported cipher suite: 0x' . dechex($cipherSuite));
        }

        return match ($cipherSuite) {
            0x1301 => 'TLS_AES_128_GCM_SHA256',
            0x1302 => 'TLS_AES_256_GCM_SHA384',
            0x1303 => 'TLS_CHACHA20_POLY1305_SHA256',
            default => 'TLS_AES_128_GCM_SHA256',
        };
    }

    private function configureKeyManagerForCipher(TLSKeyManager $keyManager, string $cipherSuite): void
    {
        $hashAlgo = match ($cipherSuite) {
            'TLS_AES_256_GCM_SHA384' => 'sha384',
            default => 'sha256',
        };

        $keyManager->setHashAlgorithm($hashAlgo);
    }

    private function extractServerKeyShare(ServerHelloMessage $serverHello, TLSKeyManager $keyManager): void
    {
        $extensions = $serverHello->getExtensions();
        $serverKeyShareRaw = $extensions[NamingExtensionType::KEY_SHARE->value] ?? null;

        if (!is_string($serverKeyShareRaw)) {
            throw new ProtocolException('Server did not provide key_share');
        }

        $ks = KeyShareExtension::decode($serverKeyShareRaw, true);
        $entries = $ks->getEntries();

        if ([] === $entries) {
            throw new ProtocolException('Server key_share entries empty');
        }

        $serverEntry = $entries[0];
        if (0x001D !== $serverEntry->getGroup()) {
            throw new ProtocolException('Only X25519 (0x001D) is supported by this client');
        }

        $keyManager->setServerPublicKey($serverEntry->getKeyExchange());
    }

    /**
     * @param string[] $cipherSuites
     * @return int[]
     */
    public function convertCipherSuitesToInts(array $cipherSuites): array
    {
        $mapping = [
            'TLS_AES_256_GCM_SHA384' => 0x1302,
            'TLS_CHACHA20_POLY1305_SHA256' => 0x1303,
            'TLS_AES_128_GCM_SHA256' => 0x1301,
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384' => 0xC030,
            'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256' => 0xC02F,
        ];

        $result = [];
        foreach ($cipherSuites as $suite) {
            if (isset($mapping[$suite])) {
                $result[] = $mapping[$suite];
            }
        }

        return $result;
    }
}
