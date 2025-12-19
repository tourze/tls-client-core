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
        $version = (string) ($this->options['version'] ?? 'auto');

        $sslOptions = [
            'SNI_enabled' => true,
            'peer_name' => $this->hostname,
            'verify_peer' => true,
            'verify_peer_name' => true,
            'allow_self_signed' => false,
        ];

        $cryptoMethod = $this->resolveCryptoMethod($version);
        if (null !== $cryptoMethod) {
            // 明确限制协议版本，避免与上层 options['version'] 语义不一致
            $sslOptions['crypto_method'] = $cryptoMethod;
        }

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

    /**
     * 将版本字符串映射为 PHP 流加密方法常量。
     *
     * @return int|null 返回 null 表示交给 OpenSSL 自动协商
     */
    private function resolveCryptoMethod(string $version): ?int
    {
        $version = trim($version);

        if ('' === $version || 'auto' === $version) {
            return $this->resolveAutoCryptoMethod();
        }

        return $this->resolveSpecificCryptoMethod($version);
    }

    /**
     * 自动协商加密方法（优先 TLS 1.2/1.3）
     */
    private function resolveAutoCryptoMethod(): ?int
    {
        $tls12 = $this->getCryptoConstant('STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT');
        $tls13 = $this->getCryptoConstant('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT');

        if (null !== $tls12 && null !== $tls13) {
            return $tls12 | $tls13;
        }

        return $tls12 ?? $this->getCryptoConstant('STREAM_CRYPTO_METHOD_TLS_CLIENT');
    }

    /**
     * 解析指定版本的加密方法
     */
    private function resolveSpecificCryptoMethod(string $version): ?int
    {
        $constantMap = [
            '1.0' => 'STREAM_CRYPTO_METHOD_TLSv1_0_CLIENT',
            '1.1' => 'STREAM_CRYPTO_METHOD_TLSv1_1_CLIENT',
            '1.2' => 'STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT',
            '1.3' => 'STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT',
        ];

        $constant = $constantMap[$version] ?? null;

        return null !== $constant ? $this->getCryptoConstant($constant) : null;
    }

    /**
     * 安全获取加密常量值
     */
    private function getCryptoConstant(string $constantName): ?int
    {
        return \defined($constantName) ? \constant($constantName) : null;
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
        return $meta['crypto'] ?? [];
    }
}
