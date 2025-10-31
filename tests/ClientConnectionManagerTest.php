<?php

declare(strict_types=1);

namespace Tourze\TLSClientCore\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSClientCore\ClientConnectionManager;
use Tourze\TLSCommon\Exception\TLSException;

/**
 * ClientConnectionManager测试
 *
 * @internal
 */
#[CoversClass(ClientConnectionManager::class)]
final class ClientConnectionManagerTest extends TestCase
{
    private ClientConnectionManager $connectionManager;

    public function testGetHostname(): void
    {
        $this->assertSame('example.com', $this->connectionManager->getHostname());
    }

    public function testGetPort(): void
    {
        $this->assertSame(443, $this->connectionManager->getPort());
    }

    public function testGetOptions(): void
    {
        $expected = [
            'timeout' => 30,
            'version' => '1.3',
        ];

        $this->assertSame($expected, $this->connectionManager->getOptions());
    }

    public function testInitialConnectionState(): void
    {
        $this->assertFalse($this->connectionManager->isConnected());
    }

    public function testSendClientHelloWithoutConnection(): void
    {
        $this->expectException(TLSException::class);
        $this->expectExceptionMessage('Connection not established');

        $this->connectionManager->sendClientHello();
    }

    public function testReceiveMessageWithoutConnection(): void
    {
        $this->expectException(TLSException::class);
        $this->expectExceptionMessage('Connection not established');

        $this->connectionManager->receiveMessage();
    }

    public function testSendApplicationDataWithoutConnection(): void
    {
        $this->expectException(TLSException::class);
        $this->expectExceptionMessage('Connection not established');

        $this->connectionManager->sendApplicationData('test data');
    }

    public function testReceiveApplicationDataWithoutConnection(): void
    {
        $this->expectException(TLSException::class);
        $this->expectExceptionMessage('Connection not established');

        $this->connectionManager->receiveApplicationData();
    }

    public function testProcessApplicationDataWithoutConnection(): void
    {
        $this->expectException(TLSException::class);
        $this->expectExceptionMessage('Connection not established');

        $this->connectionManager->processApplicationData('test data');
    }

    public function testSendClientFinishedWithoutConnection(): void
    {
        $this->expectException(TLSException::class);
        $this->expectExceptionMessage('Connection not established');

        $this->connectionManager->sendClientFinished();
    }

    public function testClose(): void
    {
        $this->connectionManager->close();
        $this->assertFalse($this->connectionManager->isConnected());
    }

    public function testCloseMultipleTimes(): void
    {
        $this->connectionManager->close();
        $this->assertFalse($this->connectionManager->isConnected());

        // 再次关闭应该不会出错
        $this->connectionManager->close();
        $this->assertFalse($this->connectionManager->isConnected());
    }

    public function testConstructorWithDefaultOptions(): void
    {
        $manager = new ClientConnectionManager('test.com');

        $this->assertSame('test.com', $manager->getHostname());
        $this->assertSame(443, $manager->getPort());
        $this->assertSame([], $manager->getOptions());
    }

    public function testConstructorWithCustomPort(): void
    {
        $manager = new ClientConnectionManager('test.com', 8443);

        $this->assertSame('test.com', $manager->getHostname());
        $this->assertSame(8443, $manager->getPort());
    }

    public function testConstructorWithCompleteOptions(): void
    {
        $options = [
            'timeout' => 60,
            'version' => '1.2',
            'cipher_suites' => ['TLS_AES_256_GCM_SHA384'],
            'extensions' => [
                'server_name' => 'custom.com',
                'supported_groups' => ['x25519'],
            ],
        ];

        $manager = new ClientConnectionManager('test.com', 443, $options);

        $this->assertSame($options, $manager->getOptions());
    }

    public function testEstablishConnectionFailure(): void
    {
        // 测试连接到无效地址
        $manager = new ClientConnectionManager('invalid.nonexistent.domain.test', 12345);

        $this->expectException(TLSException::class);
        $this->expectExceptionMessageMatches('/Failed to connect to invalid\.nonexistent\.domain\.test:12345/');

        $manager->establishConnection();
    }

    public function testEmptyHostname(): void
    {
        $manager = new ClientConnectionManager('');
        $this->assertSame('', $manager->getHostname());
    }

    public function testZeroPort(): void
    {
        $manager = new ClientConnectionManager('example.com', 0);
        $this->assertSame(0, $manager->getPort());
    }

    public function testNegativePort(): void
    {
        $manager = new ClientConnectionManager('example.com', -1);
        $this->assertSame(-1, $manager->getPort());
    }

    public function testLargePort(): void
    {
        $manager = new ClientConnectionManager('example.com', 65535);
        $this->assertSame(65535, $manager->getPort());
    }

    public function testOptionsImmutability(): void
    {
        $options = ['timeout' => 30];
        $manager = new ClientConnectionManager('example.com', 443, $options);

        // 修改原数组
        $options['timeout'] = 60;

        // 验证管理器中的选项没有改变
        $this->assertSame(30, $manager->getOptions()['timeout']);
    }

    public function testMultipleInstances(): void
    {
        $manager1 = new ClientConnectionManager('host1.com');
        $manager2 = new ClientConnectionManager('host2.com');

        $this->assertNotSame($manager1, $manager2);
        $this->assertSame('host1.com', $manager1->getHostname());
        $this->assertSame('host2.com', $manager2->getHostname());
    }

    public function testConnectionStateAfterFailure(): void
    {
        $manager = new ClientConnectionManager('invalid.domain.test', 12345);

        try {
            $manager->establishConnection();
        } catch (TLSException $e) {
            // 预期的异常
        }

        $this->assertFalse($manager->isConnected());
    }

    public function testValidHostnameFormats(): void
    {
        $hostnames = [
            'example.com',
            'sub.example.com',
            'localhost',
            '127.0.0.1',
            '::1',
            'example-with-dash.com',
        ];

        foreach ($hostnames as $hostname) {
            $manager = new ClientConnectionManager($hostname);
            $this->assertSame($hostname, $manager->getHostname());
        }
    }

    public function testPortRange(): void
    {
        $ports = [1, 80, 443, 8080, 8443, 65535];

        foreach ($ports as $port) {
            $manager = new ClientConnectionManager('example.com', $port);
            $this->assertSame($port, $manager->getPort());
        }
    }

    public function testProcessServerHello(): void
    {
        // 由于 processServerHello 需要 ServerHelloMessage::decode，这里需要 mock 或者简化测试
        // 考虑到方法内部复杂性，我们先验证方法存在且能处理无效消息
        $this->expectException(\Exception::class);

        $invalidMessage = 'invalid_server_hello_data';
        $this->connectionManager->processServerHello($invalidMessage);
    }

    public function testProcessCertificate(): void
    {
        // 测试 processCertificate 方法存在且可以调用
        // 由于这是空实现，我们只验证方法不会抛出异常
        $message = 'certificate_data';
        $this->connectionManager->processCertificate($message);

        // 验证方法执行后连接状态未改变
        $this->assertFalse($this->connectionManager->isConnected());
    }

    public function testProcessCertificateVerify(): void
    {
        // 测试 processCertificateVerify 方法存在且可以调用
        // 由于这是空实现，我们只验证方法不会抛出异常
        $message = 'certificate_verify_data';
        $this->connectionManager->processCertificateVerify($message);

        // 验证方法执行后连接状态未改变
        $this->assertFalse($this->connectionManager->isConnected());
    }

    public function testProcessEncryptedExtensions(): void
    {
        // 测试 processEncryptedExtensions 方法能够正常执行
        $message = "\x08\x00\x00\x00\x00\x00\x00\x00"; // 模拟 EncryptedExtensions 消息

        // 验证方法可以正常调用而不抛出异常
        $this->connectionManager->processEncryptedExtensions($message);

        // 通过反射验证 handshake transcript 被更新
        $reflection = new \ReflectionClass($this->connectionManager);
        $property = $reflection->getProperty('handshakeTranscript');
        $property->setAccessible(true);
        $transcript = $property->getValue($this->connectionManager);

        $this->assertStringEndsWith($message, $transcript);
    }

    public function testProcessServerFinished(): void
    {
        // 测试 processServerFinished 方法在没有 handshake secrets 时抛出异常
        $message = "\x14\x00\x00\x20" . str_repeat("\x00", 32); // 模拟 Finished 消息

        $this->expectException(TLSException::class);
        $this->expectExceptionMessage('Handshake secrets not ready');

        $this->connectionManager->processServerFinished($message);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->connectionManager = new ClientConnectionManager('example.com', 443, [
            'timeout' => 30,
            'version' => '1.3',
        ]);
    }
}
