# TLS Client Core

[English](README.md) | [中文](README.zh-CN.md)

[![Latest Version](https://img.shields.io/packagist/v/tourze/tls-client-core.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-client-core)
[![Build Status](https://img.shields.io/github/actions/workflow/status/tourze/php-monorepo/test.yml?branch=master&style=flat-square)](https://github.com/tourze/php-monorepo/actions)
[![Quality Score](https://img.shields.io/scrutinizer/g/tourze/php-monorepo.svg?style=flat-square)](https://scrutinizer-ci.com/g/tourze/php-monorepo)
[![Total Downloads](https://img.shields.io/packagist/dt/tourze/tls-client-core.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-client-core)
[![License](https://img.shields.io/packagist/l/tourze/tls-client-core.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-client-core)
[![Coverage Status](https://img.shields.io/codecov/c/github/tourze/php-monorepo.svg?style=flat-square)](https://codecov.io/gh/tourze/php-monorepo)

A comprehensive TLS client core implementation for PHP 8.1+, providing secure TLS 1.2/1.3 client functionality with state machine management and connection handling.

## Features

- **TLS 1.2/1.3 Support**: Full implementation of modern TLS protocol versions
- **State Machine Management**: Robust client state machine with proper handshake flow
- **Connection Management**: Automatic connection establishment and cleanup
- **Cipher Suite Negotiation**: Support for modern cipher suites (AES-GCM, ChaCha20-Poly1305)
- **Extensible Architecture**: Clean interfaces for extension and customization
- **Type Safety**: Full PHP 8.1+ type declarations with enums

## Installation

```bash
composer require tourze/tls-client-core
```

## Requirements

- PHP 8.1 or higher
- ext-openssl
- ext-sockets

## Quick Start

```php
<?php

use Tourze\TLSClientCore\TLSClientCore;

// Create TLS client instance
$client = new TLSClientCore('example.com', 443, [
    'timeout' => 30,
    'version' => '1.3',
    'cipher_suites' => [
        'TLS_AES_256_GCM_SHA384',
        'TLS_CHACHA20_POLY1305_SHA256',
        'TLS_AES_128_GCM_SHA256',
    ],
]);

// Establish TLS connection
$client->connect();

// Send application data
$client->sendData('GET / HTTP/1.1\r\nHost: example.com\r\n\r\n');

// Receive response
$response = $client->receiveData();

// Close connection
$client->close();
```

### State Machine Usage

```php
<?php

use Tourze\TLSClientCore\TLSClientCore;
use Tourze\TLSClientCore\ClientStateEnum;

$client = new TLSClientCore('example.com');
$stateMachine = $client->getStateMachine();

// Check current state
if ($stateMachine->getCurrentClientState() === ClientStateEnum::INITIAL) {
    echo "Client is in initial state\n";
}

// Connect and monitor state changes
$client->connect();

if ($stateMachine->isHandshakeCompleted()) {
    echo "Handshake completed successfully\n";
    echo "Current state: " . $stateMachine->getCurrentStateDescription() . "\n";
}
```

### Connection Management

```php
<?php

use Tourze\TLSClientCore\TLSClientCore;

$client = new TLSClientCore('api.example.com', 443, [
    'timeout' => 15,
    'version' => '1.3',
]);

$connectionManager = $client->getConnectionManager();

// Check connection status
if ($connectionManager->isConnected()) {
    echo "Connection established to: " . $connectionManager->getHostname() . ":" . $connectionManager->getPort() . "\n";
}
```

## API Reference

### TLSClientCore

- `__construct(string $hostname, int $port = 443, array $options = [])` - Create client instance
- `connect(): void` - Establish TLS connection
- `sendData(string $data): void` - Send application data
- `receiveData(): string` - Receive application data
- `close(): void` - Close connection
- `isEstablished(): bool` - Check if connection is established
- `getState(): string` - Get current connection state
- `getConnectionManager(): ClientConnectionManager` - Get connection manager
- `getStateMachine(): ClientStateMachine` - Get state machine

### ClientStateMachine

- `getCurrentClientState(): ClientStateEnum` - Get current state
- `isHandshakeCompleted(): bool` - Check if handshake is complete
- `getCurrentStateDescription(): string` - Get human-readable state description
- `canSendApplicationData(): bool` - Check if can send application data
- `canReceiveApplicationData(): bool` - Check if can receive application data
- `reset(): void` - Reset state machine

### ClientStateEnum

Available states:
- `INITIAL` - Initial state
- `WAIT_SERVER_HELLO` - Waiting for ServerHello
- `WAIT_ENCRYPTED_EXTENSIONS` - Waiting for EncryptedExtensions
- `WAIT_CERTIFICATE` - Waiting for Certificate
- `WAIT_CERTIFICATE_VERIFY` - Waiting for CertificateVerify
- `WAIT_FINISHED` - Waiting for Finished
- `CONNECTED` - Connection established
- `ERROR` - Error state

## Configuration Options

- `timeout` (int): Connection timeout in seconds (default: 30)
- `version` (string): TLS version ('1.2' or '1.3', default: '1.3')
- `cipher_suites` (array): Supported cipher suites

## Contributing

Please see [CONTRIBUTING.md](https://github.com/tourze/php-monorepo/blob/master/CONTRIBUTING.md) for details.

## Testing

```bash
# Run tests
vendor/bin/phpunit packages/tls-client-core/tests

# Run PHPStan analysis
vendor/bin/phpstan analyse packages/tls-client-core
```

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.
