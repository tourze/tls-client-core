<?php

declare(strict_types=1);

namespace Tourze\TLSClientCore;

use Tourze\TLSCommon\Exception\ProtocolException;
use Tourze\TLSCommon\Exception\TLSException;

/**
 * 基于 PHP OpenSSL 的原生 TLS 客户端适配器
 *
 * 说明：
 * - 用于端到端验证握手/加解密是否可用（依赖系统 OpenSSL 实现）
 * - 作为 tls-client-core 的临时/验证路径（options['use_native']=true 时启用）
 */
final class NativeTLSClient
{
    /** @var resource|null */
    private $stream;

    /** @var array<string,mixed> */
    private array $options;

    /**
     * @param array<string, mixed> $options
     */
    public function __construct(
        private readonly string $hostname,
        private readonly int $port = 443,
        array $options = [],
    ) {
        $this->options = $options;
    }

    public function connect(): void
    {
        if (null !== $this->stream) {
            return;
        }

        $timeout = (int) ($this->options['timeout'] ?? 30);
        $version = (string) ($this->options['version'] ?? '1.3');

        $sslOptions = [
            'SNI_enabled' => true,
            'peer_name' => $this->hostname,
            'verify_peer' => true,
            'verify_peer_name' => true,
            'allow_self_signed' => false,
            // crypto_method 交给 OpenSSL 自动协商（保留默认更兼容）
        ];

        $context = stream_context_create(['ssl' => $sslOptions]);

        $errno = 0;
        $errstr = '';
        $uri = sprintf('tls://%s:%d', $this->hostname, $this->port);

        $stream = @stream_socket_client(
            $uri,
            $errno,
            $errstr,
            $timeout,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if (false === $stream) {
            throw new ProtocolException("Native TLS connect failed: {$uri} - ({$errno}) {$errstr}");
        }

        stream_set_blocking($stream, true);
        stream_set_timeout($stream, $timeout);

        $this->stream = $stream;
    }

    public function close(): void
    {
        if (is_resource($this->stream)) {
            @fclose($this->stream);
        }
        $this->stream = null;
    }

    public function send(string $data): void
    {
        if (!is_resource($this->stream)) {
            throw new ProtocolException('Native TLS stream not connected');
        }

        $total = 0;
        $length = strlen($data);
        while ($total < $length) {
            $written = @fwrite($this->stream, substr($data, $total));
            if (false === $written || 0 === $written) {
                $meta = stream_get_meta_data($this->stream);
                throw new ProtocolException('Native TLS write failed' . ($meta['timed_out'] ? ' (timeout)' : ''));
            }
            $total += $written;
        }
    }

    public function receive(int $maxBytes = 8192): string
    {
        if (!is_resource($this->stream)) {
            throw new ProtocolException('Native TLS stream not connected');
        }

        $data = @fread($this->stream, max(1, $maxBytes));
        if (false === $data) {
            $meta = stream_get_meta_data($this->stream);
            throw new ProtocolException('Native TLS read failed' . ($meta['timed_out'] ? ' (timeout)' : ''));
        }

        return $data;
    }

    /**
     * 检查连接是否已建立
     */
    public function isEstablished(): bool
    {
        return is_resource($this->stream);
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
     * @return array<string,mixed>
     */
    public function getCryptoMeta(): array
    {
        if (!is_resource($this->stream)) {
            return [];
        }

        $meta = stream_get_meta_data($this->stream);

        // @phpstan-ignore-next-line - crypto key exists in TLS stream metadata
        return $meta['crypto'] ?? [];
    }
}
