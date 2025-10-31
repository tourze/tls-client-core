<?php

declare(strict_types=1);

namespace Tourze\TLSClientCore\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSClientCore\ClientConnectionManager;
use Tourze\TLSClientCore\ClientStateEnum;
use Tourze\TLSClientCore\ClientStateMachine;
use Tourze\TLSClientCore\TLSClientCore;
use Tourze\TLSCommon\Exception\TLSException;

/**
 * TLSClientCore测试
 *
 * @internal
 */
#[CoversClass(TLSClientCore::class)]
final class TLSClientCoreTest extends TestCase
{
    private TLSClientCore $client;

    protected function setUp(): void
    {
        parent::setUp();

        $this->client = new TLSClientCore('example.com', 443, [
            'timeout' => 30,
            'version' => '1.3',
        ]);
    }

    public function testGetName(): void
    {
        $this->assertSame('TLS Client', $this->client->getName());
    }

    public function testGetVersion(): void
    {
        $this->assertSame(13, $this->client->getVersion());
    }

    public function testGetVersionDefault(): void
    {
        $client = new TLSClientCore('example.com');
        $this->assertSame(13, $client->getVersion());
    }

    public function testGetVersionCustom(): void
    {
        $client = new TLSClientCore('example.com', 443, ['version' => '1.2']);
        $this->assertSame(12, $client->getVersion());
    }

    public function testInitialState(): void
    {
        $this->assertFalse($this->client->isEstablished());
        $this->assertSame('initial', $this->client->getState());
    }

    public function testProcessWithoutEstablishedConnection(): void
    {
        $this->expectException(TLSException::class);
        $this->expectExceptionMessage('TLS connection not established');

        $this->client->process('test data');
    }

    public function testSendDataWithoutEstablishedConnection(): void
    {
        $this->expectException(TLSException::class);
        $this->expectExceptionMessage('Connection not established');

        $this->client->sendData('test data');
    }

    public function testReceiveDataWithoutEstablishedConnection(): void
    {
        $this->expectException(TLSException::class);
        $this->expectExceptionMessage('Connection not established');

        $this->client->receiveData();
    }

    public function testGetConnectionManager(): void
    {
        $connectionManager = $this->client->getConnectionManager();
        $this->assertInstanceOf(ClientConnectionManager::class, $connectionManager);
    }

    public function testGetStateMachine(): void
    {
        $stateMachine = $this->client->getStateMachine();
        $this->assertInstanceOf(ClientStateMachine::class, $stateMachine);
    }

    public function testClose(): void
    {
        $this->client->close();
        $this->assertFalse($this->client->isEstablished());
        $this->assertSame('closed', $this->client->getState());
    }

    public function testClientWithDifferentPort(): void
    {
        $client = new TLSClientCore('example.com', 8443);
        $this->assertSame('TLS Client', $client->getName());
    }

    public function testClientWithOptions(): void
    {
        $options = [
            'version' => '1.2',
            'timeout' => 60,
            'cipher_suites' => ['TLS_AES_256_GCM_SHA384'],
        ];

        $client = new TLSClientCore('test.example.com', 443, $options);
        $this->assertSame(12, $client->getVersion());
    }

    public function testMultipleInstances(): void
    {
        $client1 = new TLSClientCore('host1.com');
        $client2 = new TLSClientCore('host2.com');

        $this->assertNotSame($client1, $client2);
        $this->assertSame('initial', $client1->getState());
        $this->assertSame('initial', $client2->getState());
    }

    public function testStateTransitionDuringConnect(): void
    {
        $this->assertSame('initial', $this->client->getState());

        // 模拟连接失败 - 使用一个不存在的域名
        try {
            $client = new TLSClientCore('nonexistent.invalid.domain.12345', 443);
            $client->connect();
            self::fail('Expected TLSException to be thrown');
        } catch (TLSException $e) {
            $this->assertStringContainsString('Failed to establish TLS connection', $e->getMessage());
        }
    }

    public function testConnectionManagerHostname(): void
    {
        $connectionManager = $this->client->getConnectionManager();
        $this->assertSame('example.com', $connectionManager->getHostname());
    }

    public function testConnectionManagerPort(): void
    {
        $connectionManager = $this->client->getConnectionManager();
        $this->assertSame(443, $connectionManager->getPort());
    }

    public function testStateMachineInitialState(): void
    {
        $stateMachine = $this->client->getStateMachine();
        $this->assertSame(ClientStateEnum::INITIAL, $stateMachine->getCurrentClientState());
        $this->assertFalse($stateMachine->isHandshakeCompleted());
        $this->assertFalse($stateMachine->isInErrorState());
    }

    public function testCloseMultipleTimes(): void
    {
        $this->client->close();
        $this->assertSame('closed', $this->client->getState());

        // 再次关闭应该不会出错
        $this->client->close();
        $this->assertSame('closed', $this->client->getState());
    }

    public function testEmptyHostname(): void
    {
        $client = new TLSClientCore('');
        $this->assertSame('', $client->getConnectionManager()->getHostname());
    }

    public function testZeroPort(): void
    {
        $client = new TLSClientCore('example.com', 0);
        $this->assertSame(0, $client->getConnectionManager()->getPort());
    }

    public function testNegativePort(): void
    {
        $client = new TLSClientCore('example.com', -1);
        $this->assertSame(-1, $client->getConnectionManager()->getPort());
    }

    public function testLargePort(): void
    {
        $client = new TLSClientCore('example.com', 65535);
        $this->assertSame(65535, $client->getConnectionManager()->getPort());
    }

    public function testConnectionManagerOptions(): void
    {
        $options = ['timeout' => 120, 'version' => '1.2'];
        $client = new TLSClientCore('example.com', 443, $options);

        $connectionManager = $client->getConnectionManager();
        $this->assertSame($options, $connectionManager->getOptions());
    }
}
