<?php

declare(strict_types=1);

namespace Tourze\TLSClientCore\Crypto;

use Tourze\TLSCommon\Exception\ProtocolException;
use Tourze\TLSCommon\Exception\TLSException;
use Tourze\TLSCryptoHash\Tls\TLS13HKDF;
use Tourze\TLSCryptoKeyExchange\X25519 as X25519KeyExchange;
use Tourze\TLSRecord\CipherState;

/**
 * TLS密钥管理器 - 专门处理密钥生成、派生和状态管理
 */
final class TLSKeyManager
{
    private ?string $clientPrivateKey = null;

    private ?string $clientPublicKey = null;

    private ?string $serverPublicKey = null;

    private ?string $sharedSecret = null;

    private ?TLS13HKDF $hkdf = null;

    private ?string $clientHsTrafficSecret = null;

    private ?string $serverHsTrafficSecret = null;

    private ?string $handshakeSecret = null;

    private ?string $clientAppTrafficSecret = null;

    private ?string $serverAppTrafficSecret = null;

    public function __construct(string $hashAlgo = 'sha256')
    {
        $this->hkdf = new TLS13HKDF($hashAlgo);
    }

    public function generateClientKeyPair(): void
    {
        $kex = new X25519KeyExchange();
        $pair = $kex->generateKeyPair();
        $this->clientPrivateKey = $pair['privateKey'];
        $this->clientPublicKey = $pair['publicKey'];

        if (null !== $this->clientPublicKey && 32 !== strlen($this->clientPublicKey)) {
            $this->clientPublicKey = substr($this->clientPublicKey, 0, 32);
        }
    }

    public function getClientPublicKey(): ?string
    {
        return $this->clientPublicKey;
    }

    public function setServerPublicKey(string $serverPublicKey): void
    {
        $this->serverPublicKey = $serverPublicKey;
    }

    public function computeSharedSecret(): void
    {
        if (null === $this->clientPrivateKey || null === $this->serverPublicKey) {
            throw new ProtocolException('Missing key materials for KEX');
        }

        $kex = new X25519KeyExchange();
        $this->sharedSecret = $kex->computeSharedSecret($this->clientPrivateKey, $this->serverPublicKey);
    }

    public function deriveHandshakeSecrets(string $handshakeTranscript): void
    {
        if (null === $this->hkdf || null === $this->sharedSecret) {
            throw new ProtocolException('HKDF or shared secret not ready');
        }

        $earlySecret = $this->hkdf->deriveEarlySecret('');
        $this->handshakeSecret = $this->hkdf->deriveHandshakeSecret($earlySecret, $this->sharedSecret);

        $this->clientHsTrafficSecret = $this->hkdf->deriveSecret($this->handshakeSecret, 'c hs traffic', $handshakeTranscript);
        $this->serverHsTrafficSecret = $this->hkdf->deriveSecret($this->handshakeSecret, 's hs traffic', $handshakeTranscript);
    }

    public function deriveApplicationSecrets(string $handshakeTranscript): void
    {
        if (null === $this->hkdf || null === $this->handshakeSecret) {
            throw new ProtocolException('HKDF or handshake secret not ready');
        }

        $master = $this->hkdf->deriveMasterSecret($this->handshakeSecret);
        $this->clientAppTrafficSecret = $this->hkdf->deriveSecret($master, 'c ap traffic', $handshakeTranscript);
        $this->serverAppTrafficSecret = $this->hkdf->deriveSecret($master, 's ap traffic', $handshakeTranscript);
    }

    /**
     * @return array<string, CipherState>
     */
    public function createHandshakeCipherStates(string $cipherSuite): array
    {
        if (null === $this->hkdf || null === $this->clientHsTrafficSecret || null === $this->serverHsTrafficSecret) {
            throw new ProtocolException('Handshake secrets not ready');
        }

        [$keyLen, $ivLen] = $this->getKeyIvLengthForCipher($cipherSuite);

        $clientKey = $this->hkdf->expandLabel($this->clientHsTrafficSecret, 'key', '', $keyLen);
        $clientIV = $this->hkdf->expandLabel($this->clientHsTrafficSecret, 'iv', '', $ivLen);
        $serverKey = $this->hkdf->expandLabel($this->serverHsTrafficSecret, 'key', '', $keyLen);
        $serverIV = $this->hkdf->expandLabel($this->serverHsTrafficSecret, 'iv', '', $ivLen);

        return [
            'client' => new CipherState($cipherSuite, $clientKey, $clientIV, '', 0x0304),
            'server' => new CipherState($cipherSuite, $serverKey, $serverIV, '', 0x0304),
        ];
    }

    /**
     * @return array<string, CipherState>
     */
    public function createApplicationCipherStates(string $cipherSuite): array
    {
        if (null === $this->hkdf || null === $this->clientAppTrafficSecret || null === $this->serverAppTrafficSecret) {
            throw new ProtocolException('Application secrets not ready');
        }

        [$keyLen, $ivLen] = $this->getKeyIvLengthForCipher($cipherSuite);

        $clientKey = $this->hkdf->expandLabel($this->clientAppTrafficSecret, 'key', '', $keyLen);
        $clientIV = $this->hkdf->expandLabel($this->clientAppTrafficSecret, 'iv', '', $ivLen);
        $serverKey = $this->hkdf->expandLabel($this->serverAppTrafficSecret, 'key', '', $keyLen);
        $serverIV = $this->hkdf->expandLabel($this->serverAppTrafficSecret, 'iv', '', $ivLen);

        return [
            'client' => new CipherState($cipherSuite, $clientKey, $clientIV, '', 0x0304),
            'server' => new CipherState($cipherSuite, $serverKey, $serverIV, '', 0x0304),
        ];
    }

    public function createFinishedVerifyData(string $handshakeTranscript, bool $isClient = true): string
    {
        if (null === $this->hkdf) {
            throw new ProtocolException('HKDF not ready');
        }

        $trafficSecret = $isClient ? $this->clientHsTrafficSecret : $this->serverHsTrafficSecret;
        if (null === $trafficSecret) {
            throw new ProtocolException('Handshake secrets not ready');
        }

        $hashAlgo = $this->hkdf->getHashAlgorithm();
        $handshakeHash = hash($hashAlgo, $handshakeTranscript, true);
        $finishedKey = $this->hkdf->expandLabel($trafficSecret, 'finished', '', $this->hkdf->getHashLength());

        return hash_hmac($hashAlgo, $handshakeHash, $finishedKey, true);
    }

    public function verifyFinishedMessage(string $verifyData, string $handshakeTranscript, bool $isClient = false): bool
    {
        $expected = $this->createFinishedVerifyData($handshakeTranscript, $isClient);

        return hash_equals($expected, $verifyData);
    }

    public function setHashAlgorithm(string $hashAlgo): void
    {
        if (null !== $this->hkdf) {
            $this->hkdf->setHashAlgorithm($hashAlgo);
        }
    }

    /**
     * @return array<int>
     */
    private function getKeyIvLengthForCipher(string $cipherSuite): array
    {
        return match ($cipherSuite) {
            'TLS_AES_128_GCM_SHA256' => [16, 12],
            'TLS_CHACHA20_POLY1305_SHA256' => [32, 12],
            'TLS_AES_256_GCM_SHA384' => [32, 12],
            default => [16, 12],
        };
    }
}
