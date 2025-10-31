<?php

declare(strict_types=1);

namespace Tourze\TLSClientCore;

use Tourze\EnumExtra\Itemable;
use Tourze\EnumExtra\ItemTrait;
use Tourze\EnumExtra\Labelable;
use Tourze\EnumExtra\Selectable;
use Tourze\EnumExtra\SelectTrait;

/**
 * TLS客户端状态枚举
 */
enum ClientStateEnum: string implements Itemable, Labelable, Selectable
{
    use ItemTrait;
    use SelectTrait;
    case INITIAL = 'initial';
    case WAIT_SERVER_HELLO = 'wait_server_hello';
    case WAIT_ENCRYPTED_EXTENSIONS = 'wait_encrypted_extensions';
    case WAIT_CERTIFICATE = 'wait_certificate';
    case WAIT_CERTIFICATE_VERIFY = 'wait_certificate_verify';
    case WAIT_FINISHED = 'wait_finished';
    case CONNECTED = 'connected';
    case ERROR = 'error';

    /**
     * 获取状态的标签文本
     */
    public function getLabel(): string
    {
        return match ($this) {
            self::INITIAL => 'Initial',
            self::WAIT_SERVER_HELLO => 'Wait Server Hello',
            self::WAIT_ENCRYPTED_EXTENSIONS => 'Wait Encrypted Extensions',
            self::WAIT_CERTIFICATE => 'Wait Certificate',
            self::WAIT_CERTIFICATE_VERIFY => 'Wait Certificate Verify',
            self::WAIT_FINISHED => 'Wait Finished',
            self::CONNECTED => 'Connected',
            self::ERROR => 'Error',
        };
    }

    /**
     * 获取状态的可读名称
     */
    public function getDisplayName(): string
    {
        return $this->getLabel();
    }

    /**
     * 是否为等待状态
     */
    public function isWaitingState(): bool
    {
        return match ($this) {
            self::WAIT_SERVER_HELLO,
            self::WAIT_ENCRYPTED_EXTENSIONS,
            self::WAIT_CERTIFICATE,
            self::WAIT_CERTIFICATE_VERIFY,
            self::WAIT_FINISHED => true,
            default => false,
        };
    }

    /**
     * 是否为终端状态
     */
    public function isTerminalState(): bool
    {
        return match ($this) {
            self::CONNECTED,
            self::ERROR => true,
            default => false,
        };
    }

    /**
     * 获取下一个预期状态
     */
    public function getNextExpectedState(): ?self
    {
        return match ($this) {
            self::INITIAL => self::WAIT_SERVER_HELLO,
            self::WAIT_SERVER_HELLO => self::WAIT_ENCRYPTED_EXTENSIONS,
            self::WAIT_ENCRYPTED_EXTENSIONS => self::WAIT_CERTIFICATE,
            self::WAIT_CERTIFICATE => self::WAIT_CERTIFICATE_VERIFY,
            self::WAIT_CERTIFICATE_VERIFY => self::WAIT_FINISHED,
            self::WAIT_FINISHED => self::CONNECTED,
            default => null,
        };
    }
}
