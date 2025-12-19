<?php

declare(strict_types=1);

namespace Tourze\TLSClientCore\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSClientCore\NativeTLSClient;
use Tourze\TLSCommon\Exception\TLSException;

/**
 * NativeTLSClient测试
 *
 * @internal
 */
#[CoversClass(NativeTLSClient::class)]
final class NativeTLSClientTest extends TestCase
{
    private NativeTLSClient $client;

    protected function setUp(): void
    {
        parent::setUp();

        $this->client = new NativeTLSClient('example.com', 443, [
            'timeout' => 30,
            'version' => '1.3',
        ]);
    }

    public function testGetHostname(): void
    {
        $this->assertSame('example.com', $this->client->getHostname());
    }

    public function testGetPort(): void
    {
        $this->assertSame(443, $this->client->getPort());
    }

    public function testGetOptions(): void
    {
        $expected = [
            'timeout' => 30,
            'version' => '1.3',
        ];

        $this->assertSame($expected, $this->client->getOptions());
    }

    public function testInitialConnectionState(): void
    {
        $this->assertFalse($this->client->isEstablished());
    }

    public function testGetCryptoMetaWithoutConnection(): void
    {
        $meta = $this->client->getCryptoMeta();
        $this->assertSame([], $meta);
    }

    public function testSendWithoutConnection(): void
    {
        $this->expectException(TLSException::class);
        $this->expectExceptionMessage('Native TLS stream not connected');

        $this->client->send('test data');
    }

    public function testReceiveWithoutConnection(): void
    {
        $this->expectException(TLSException::class);
        $this->expectExceptionMessage('Native TLS stream not connected');

        $this->client->receive();
    }

    public function testClose(): void
    {
        // 测试 close 方法不会抛出异常
        $this->client->close();
        $this->assertFalse($this->client->isEstablished());
    }

    public function testConnectFailure(): void
    {
        $client = new NativeTLSClient('nonexistent.invalid.domain.12345', 443, ['timeout' => 1]);

        $this->expectException(TLSException::class);
        $this->expectExceptionMessage('Native TLS connect failed');

        $client->connect();
    }

    public function testConnectSuccess(): void
    {
        // 跳过这个测试如果网络不可用或在CI环境中
        if (!function_exists('stream_socket_client') || false !== getenv('CI')) {
            self::markTestSkipped('Network connectivity test skipped in CI or when stream functions not available');
        }

        try {
            // 使用国内可访问的站点进行端到端验证
            $client = new NativeTLSClient('www.baidu.com', 443, ['timeout' => 5]);
            $client->connect();

            $this->assertTrue($client->isEstablished());

            // 发送一个最小的 HTTP/1.1 请求，验证读写通路可用
            $client->send("GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n");
            $response = $client->receive(4096);
            $this->assertNotSame('', $response);
            $this->assertStringContainsString('HTTP/', $response);

            $client->close();
            $this->assertFalse($client->isEstablished());
        } catch (TLSException $e) {
            // 如果连接失败，跳过测试而不是失败
            self::markTestSkipped('Network connectivity test failed: ' . $e->getMessage());
        }
    }
}
