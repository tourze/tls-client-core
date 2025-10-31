# TLS 客户端核心库

[English](README.md) | [中文](README.zh-CN.md)

[![PHP Version](https://img.shields.io/packagist/php-v/tourze/tls-client-core.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-client-core)
[![Latest Version](https://img.shields.io/packagist/v/tourze/tls-client-core.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-client-core)
[![Build Status](https://img.shields.io/github/actions/workflow/status/tourze/php-monorepo/test.yml?branch=master&style=flat-square)](https://github.com/tourze/php-monorepo/actions)
[![Quality Score](https://img.shields.io/scrutinizer/g/tourze/php-monorepo.svg?style=flat-square)](https://scrutinizer-ci.com/g/tourze/php-monorepo)
[![Total Downloads](https://img.shields.io/packagist/dt/tourze/tls-client-core.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-client-core)
[![License](https://img.shields.io/packagist/l/tourze/tls-client-core.svg?style=flat-square)](https://packagist.org/packages/tourze/tls-client-core)
[![Coverage Status](https://img.shields.io/codecov/c/github/tourze/php-monorepo.svg?style=flat-square)](https://codecov.io/gh/tourze/php-monorepo)

一个全面的 TLS 客户端实现，提供建立安全 TLS 连接的核心功能，具有正确的状态管理和握手流程控制。

## 目录

- [特性](#特性)
- [安装](#安装)
  - [系统要求](#系统要求)
- [快速开始](#快速开始)
  - [基本 TLS 连接](#基本-tls-连接)
  - [高级配置](#高级配置)
  - [状态机使用](#状态机使用)
- [API 参考](#api-参考)
  - [TLSClientCore](#tlsclientcore)
  - [ClientStateMachine](#clientstatemachine)
  - [ClientStateEnum](#clientstateenum)
- [错误处理](#错误处理)
- [贡献](#贡献)
  - [开发要求](#开发要求)
  - [运行测试](#运行测试)
- [安全](#安全)
- [许可证](#许可证)
- [致谢](#致谢)
- [更新日志](#更新日志)

## 特性

- **完整的 TLS 1.3 支持**：完整实现 TLS 1.3 协议，并向后兼容 TLS 1.2
- **状态机管理**：健壮的客户端状态机，具有正确的转换验证
- **连接管理**：高效的连接建立和清理，带有连接池功能
- **握手流程控制**：完整的握手过程实现，带有适当的错误处理
- **应用数据处理**：在已建立的 TLS 连接上安全传输应用数据
- **可扩展架构**：结构良好的代码库，关注点分离清晰

## 安装

```bash
composer require tourze/tls-client-core
```

### 系统要求

- PHP 8.1 或更高版本
- OpenSSL 扩展
- Socket 扩展

## 快速开始

### 基本 TLS 连接

```php
<?php

use Tourze\TLSClientCore\TLSClientCore;

// 创建 TLS 客户端实例
$client = new TLSClientCore('example.com', 443);

// 建立连接
$client->connect();

// 发送应用数据
$client->sendData('GET / HTTP/1.1\r\nHost: example.com\r\n\r\n');

// 接收响应
$response = $client->receiveData();

// 关闭连接
$client->close();
```

### 高级配置

```php
<?php

use Tourze\TLSClientCore\TLSClientCore;

// 使用自定义选项创建客户端
$client = new TLSClientCore('example.com', 443, [
    'version' => '1.3',
    'cipher_suites' => [
        'TLS_AES_256_GCM_SHA384',
        'TLS_CHACHA20_POLY1305_SHA256',
        'TLS_AES_128_GCM_SHA256'
    ],
    'timeout' => 30
]);

// 检查连接状态
if ($client->isEstablished()) {
    echo "当前状态：" . $client->getState();
}
```

### 状态机使用

```php
<?php

use Tourze\TLSClientCore\TLSClientCore;
use Tourze\TLSClientCore\ClientStateEnum;

$client = new TLSClientCore('example.com', 443);
$stateMachine = $client->getStateMachine();

// 监控状态转换
$client->connect();

// 检查当前状态
$currentState = $stateMachine->getCurrentClientState();
echo "当前状态：" . $currentState->getLabel();

// 检查握手是否完成
if ($stateMachine->isHandshakeCompleted()) {
    echo "握手成功完成";
}
```

## API 参考

### TLSClientCore

#### 构造函数

```php
__construct(string $hostname, int $port = 443, array $options = [])
```

#### 主要方法

- `connect()`: 建立 TLS 连接
- `sendData(string $data)`: 发送应用数据
- `receiveData()`: 接收应用数据
- `close()`: 关闭连接
- `isEstablished()`: 检查连接是否已建立
- `getState()`: 返回当前连接状态

### ClientStateMachine

#### 状态管理

- `getCurrentClientState()`: 获取当前客户端状态
- `transitionTo(HandshakeStateEnum $state)`: 转换到新状态
- `isHandshakeCompleted()`: 检查握手是否完成
- `reset()`: 重置状态机

### ClientStateEnum

#### 可用状态

- `INITIAL`: 初始状态
- `WAIT_SERVER_HELLO`: 等待服务器问候
- `WAIT_ENCRYPTED_EXTENSIONS`: 等待加密扩展
- `WAIT_CERTIFICATE`: 等待证书
- `WAIT_CERTIFICATE_VERIFY`: 等待证书验证
- `WAIT_FINISHED`: 等待完成消息
- `CONNECTED`: 成功连接
- `ERROR`: 错误状态

## 错误处理

```php
<?php

use Tourze\TLSClientCore\TLSClientCore;
use Tourze\TLSCommon\Exception\TLSException;

try {
    $client = new TLSClientCore('example.com', 443);
    $client->connect();
    $client->sendData('Hello, World!');
} catch (TLSException $e) {
    echo "TLS 错误：" . $e->getMessage();
} catch (Exception $e) {
    echo "一般错误：" . $e->getMessage();
}
```

## 贡献

1. Fork 仓库
2. 创建您的特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交您的更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 打开拉取请求

### 开发要求

- PHP 8.1+
- PHPUnit 10.0+
- PHPStan 用于静态分析

### 运行测试

```bash
# 运行所有测试
vendor/bin/phpunit

# 运行带覆盖率的测试
vendor/bin/phpunit --coverage-html coverage

# 运行静态分析
vendor/bin/phpstan analyse
```

## 安全

如果您发现任何与安全相关的问题，请发送邮件至 security@example.com，而不是使用问题追踪器。

## 许可证

MIT 许可证。请查看 [许可证文件](LICENSE) 获取更多信息。

## 致谢

- 使用 [Tourze Framework](https://github.com/tourze) 构建
- 受现代 TLS 实现启发
- 感谢所有贡献者

## 更新日志

请查看 [CHANGELOG.md](CHANGELOG.md) 了解最近更改的更多信息。 