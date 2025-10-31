<?php

declare(strict_types=1);

namespace Tourze\TLSClientCore\Tests\Crypto;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSClientCore\Crypto\TLSKeyManager;
use Tourze\TLSCommon\Exception\TLSException;

/**
 * @internal
 */
#[CoversClass(TLSKeyManager::class)]
class TLSKeyManagerTest extends TestCase
{
    private TLSKeyManager $keyManager;

    protected function setUp(): void
    {
        $this->keyManager = new TLSKeyManager();
    }

    public function testGenerateClientKeyPair(): void
    {
        $this->keyManager->generateClientKeyPair();
        $publicKey = $this->keyManager->getClientPublicKey();

        $this->assertNotNull($publicKey);
        $this->assertSame(32, strlen($publicKey));
    }

    public function testSetServerPublicKey(): void
    {
        $serverKey = random_bytes(32);
        $this->keyManager->setServerPublicKey($serverKey);

        $this->assertInstanceOf(TLSKeyManager::class, $this->keyManager);
    }

    public function testComputeSharedSecretWithoutKeys(): void
    {
        $this->expectException(TLSException::class);
        $this->expectExceptionMessage('Missing key materials for KEX');

        $this->keyManager->computeSharedSecret();
    }

    public function testComputeSharedSecret(): void
    {
        $this->keyManager->generateClientKeyPair();
        $this->keyManager->setServerPublicKey(random_bytes(32));

        $this->keyManager->computeSharedSecret();
        $this->assertInstanceOf(TLSKeyManager::class, $this->keyManager);
    }

    public function testDeriveHandshakeSecretsWithoutSharedSecret(): void
    {
        $this->expectException(TLSException::class);
        $this->expectExceptionMessage('HKDF or shared secret not ready');

        $this->keyManager->deriveHandshakeSecrets('test');
    }

    public function testCreateFinishedVerifyDataWithoutSecrets(): void
    {
        $this->expectException(TLSException::class);
        $this->expectExceptionMessage('Handshake secrets not ready');

        $this->keyManager->createFinishedVerifyData('test');
    }

    public function testSetHashAlgorithm(): void
    {
        $this->keyManager->setHashAlgorithm('sha384');

        $this->assertInstanceOf(TLSKeyManager::class, $this->keyManager);
    }

    public function testCreateHandshakeCipherStatesWithoutSecrets(): void
    {
        $this->expectException(TLSException::class);
        $this->expectExceptionMessage('Handshake secrets not ready');

        $this->keyManager->createHandshakeCipherStates('TLS_AES_128_GCM_SHA256');
    }

    public function testCreateApplicationCipherStatesWithoutSecrets(): void
    {
        $this->expectException(TLSException::class);
        $this->expectExceptionMessage('Application secrets not ready');

        $this->keyManager->createApplicationCipherStates('TLS_AES_128_GCM_SHA256');
    }

    public function testVerifyFinishedMessageWithoutSecrets(): void
    {
        $this->expectException(TLSException::class);
        $this->expectExceptionMessage('Handshake secrets not ready');

        $this->keyManager->verifyFinishedMessage('test', 'transcript');
    }

    public function testDeriveApplicationSecretsWithoutHandshakeSecret(): void
    {
        $this->expectException(TLSException::class);
        $this->expectExceptionMessage('HKDF or handshake secret not ready');

        $this->keyManager->deriveApplicationSecrets('test_transcript');
    }

    public function testDeriveApplicationSecrets(): void
    {
        $this->keyManager->generateClientKeyPair();
        $this->keyManager->setServerPublicKey(random_bytes(32));
        $this->keyManager->computeSharedSecret();

        $handshakeTranscript = 'test_handshake_transcript';
        $this->keyManager->deriveHandshakeSecrets($handshakeTranscript);

        $this->keyManager->deriveApplicationSecrets($handshakeTranscript);

        $this->assertInstanceOf(TLSKeyManager::class, $this->keyManager);

        $cipherStates = $this->keyManager->createApplicationCipherStates('TLS_AES_128_GCM_SHA256');
        $this->assertIsArray($cipherStates);
        $this->assertArrayHasKey('client', $cipherStates);
        $this->assertArrayHasKey('server', $cipherStates);
    }
}
