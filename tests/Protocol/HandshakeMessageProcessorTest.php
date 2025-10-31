<?php

declare(strict_types=1);

namespace Tourze\TLSClientCore\Tests\Protocol;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSClientCore\Crypto\TLSKeyManager;
use Tourze\TLSClientCore\Protocol\HandshakeMessageProcessor;
use Tourze\TLSCommon\Exception\TLSException;
use Tourze\TLSHandshakeMessages\Exception\InvalidMessageException;

/**
 * @internal
 */
#[CoversClass(HandshakeMessageProcessor::class)]
class HandshakeMessageProcessorTest extends TestCase
{
    private HandshakeMessageProcessor $processor;

    private TLSKeyManager $keyManager;

    protected function setUp(): void
    {
        $this->processor = new HandshakeMessageProcessor(['TLS_AES_128_GCM_SHA256']);
        $this->keyManager = new TLSKeyManager();
    }

    public function testConvertCipherSuitesToInts(): void
    {
        $cipherSuites = ['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384'];
        $result = $this->processor->convertCipherSuitesToInts($cipherSuites);

        $this->assertSame([0x1301, 0x1302], $result);
    }

    public function testConvertCipherSuitesToIntsWithUnknownSuite(): void
    {
        $cipherSuites = ['UNKNOWN_SUITE'];
        $result = $this->processor->convertCipherSuitesToInts($cipherSuites);

        $this->assertSame([], $result);
    }

    public function testProcessEncryptedExtensions(): void
    {
        $message = "\x08\x00\x00\x02\x00\x00";

        $this->processor->processEncryptedExtensions($message);
        $this->assertInstanceOf(HandshakeMessageProcessor::class, $this->processor);
    }

    public function testProcessCertificate(): void
    {
        $message = "\x0b\x00\x00\x05\x00\x00\x00\x01\x00";

        $this->processor->processCertificate($message);
        $this->assertInstanceOf(HandshakeMessageProcessor::class, $this->processor);
    }

    public function testProcessCertificateVerify(): void
    {
        $message = "\x0f\x00\x00\x08\x04\x03\x00\x04test";

        $this->processor->processCertificateVerify($message);
        $this->assertInstanceOf(HandshakeMessageProcessor::class, $this->processor);
    }

    public function testProcessServerFinishedWithInvalidMessage(): void
    {
        $this->expectException(InvalidMessageException::class);
        $this->expectExceptionMessage('Invalid message type');

        $this->processor->processServerFinished('invalid', 'transcript', $this->keyManager);
    }

    public function testProcessServerHelloWithInvalidMessage(): void
    {
        $this->expectException(InvalidMessageException::class);

        $this->processor->processServerHello('invalid_message', $this->keyManager);
    }

    public function testProcessServerHelloWithUnsupportedCipher(): void
    {
        $serverHelloData = $this->createServerHelloWithoutKeyShare(0x1304);

        $this->expectException(TLSException::class);
        $this->expectExceptionMessage('Invalid ServerHello message');

        $this->processor->processServerHello($serverHelloData, $this->keyManager);
    }

    public function testProcessServerHelloWithMissingKeyShare(): void
    {
        $this->keyManager->generateClientKeyPair();

        $serverHelloData = $this->createServerHelloWithoutKeyShare(0x1301);

        $this->expectException(TLSException::class);
        $this->expectExceptionMessage('Server did not provide key_share');

        $this->processor->processServerHello($serverHelloData, $this->keyManager);
    }

    private function createServerHelloWithoutKeyShare(int $cipherSuite): string
    {
        $version = "\x03\x03";
        $random = str_repeat("\x00", 32);
        $sessionIdLength = "\x00";
        $cipherSuiteBytes = pack('n', $cipherSuite);
        $compressionMethod = "\x00";

        $extensionsLength = "\x00\x00";

        $messageBody = $version . $random . $sessionIdLength . $cipherSuiteBytes . $compressionMethod . $extensionsLength;
        $messageLength = pack('N', strlen($messageBody))[1] . pack('N', strlen($messageBody))[2] . pack('N', strlen($messageBody))[3];

        return "\x02" . $messageLength . $messageBody;
    }
}
