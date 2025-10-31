<?php

declare(strict_types=1);

namespace Tourze\TLSClientCore\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSClientCore\ClientStateEnum;
use Tourze\TLSClientCore\ClientStateMachine;
use Tourze\TLSCommon\Exception\TLSException;

/**
 * ClientStateMachine测试
 *
 * @internal
 */
#[CoversClass(ClientStateMachine::class)]
final class ClientStateMachineTest extends TestCase
{
    private ClientStateMachine $stateMachine;

    protected function setUp(): void
    {
        parent::setUp();

        $this->stateMachine = new ClientStateMachine();
    }

    public function testInitialState(): void
    {
        $this->assertSame(ClientStateEnum::INITIAL, $this->stateMachine->getCurrentClientState());
        $this->assertFalse($this->stateMachine->isHandshakeCompleted());
        $this->assertFalse($this->stateMachine->isInErrorState());
    }

    public function testGetNextState(): void
    {
        $this->assertSame(ClientStateEnum::WAIT_SERVER_HELLO, $this->stateMachine->getNextClientState());

        $this->stateMachine->transitionToString('wait_server_hello');
        $this->assertSame(ClientStateEnum::WAIT_ENCRYPTED_EXTENSIONS, $this->stateMachine->getNextClientState());

        // 按正确顺序转换到 connected
        $this->stateMachine->transitionToString('wait_encrypted_extensions');
        $this->stateMachine->transitionToString('wait_certificate');
        $this->stateMachine->transitionToString('wait_certificate_verify');
        $this->stateMachine->transitionToString('wait_finished');
        $this->stateMachine->transitionToString('connected');
        $this->assertNull($this->stateMachine->getNextClientState());
    }

    public function testValidTransitions(): void
    {
        // INITIAL -> WAIT_SERVER_HELLO
        $this->stateMachine->transitionToString('wait_server_hello');
        $this->assertSame(ClientStateEnum::WAIT_SERVER_HELLO, $this->stateMachine->getCurrentClientState());

        // WAIT_SERVER_HELLO -> WAIT_ENCRYPTED_EXTENSIONS
        $this->stateMachine->transitionToString('wait_encrypted_extensions');
        $this->assertSame(ClientStateEnum::WAIT_ENCRYPTED_EXTENSIONS, $this->stateMachine->getCurrentClientState());

        // WAIT_ENCRYPTED_EXTENSIONS -> WAIT_CERTIFICATE
        $this->stateMachine->transitionToString('wait_certificate');
        $this->assertSame(ClientStateEnum::WAIT_CERTIFICATE, $this->stateMachine->getCurrentClientState());

        // WAIT_CERTIFICATE -> WAIT_CERTIFICATE_VERIFY
        $this->stateMachine->transitionToString('wait_certificate_verify');
        $this->assertSame(ClientStateEnum::WAIT_CERTIFICATE_VERIFY, $this->stateMachine->getCurrentClientState());

        // WAIT_CERTIFICATE_VERIFY -> WAIT_FINISHED
        $this->stateMachine->transitionToString('wait_finished');
        $this->assertSame(ClientStateEnum::WAIT_FINISHED, $this->stateMachine->getCurrentClientState());

        // WAIT_FINISHED -> CONNECTED
        $this->stateMachine->transitionToString('connected');
        $this->assertSame(ClientStateEnum::CONNECTED, $this->stateMachine->getCurrentClientState());
        $this->assertTrue($this->stateMachine->isHandshakeCompleted());
    }

    public function testInvalidStateTransition(): void
    {
        $this->expectException(TLSException::class);
        $this->expectExceptionMessage('Invalid state transition to: invalid_state');

        $this->stateMachine->transitionToString('invalid_state');
    }

    public function testInvalidStateSequence(): void
    {
        $this->expectException(TLSException::class);
        $this->expectExceptionMessage('Invalid state transition from initial to wait_certificate');

        $this->stateMachine->transitionToString('wait_certificate');
    }

    public function testErrorStateTransition(): void
    {
        $this->stateMachine->transitionToString('error');
        $this->assertSame(ClientStateEnum::ERROR, $this->stateMachine->getCurrentClientState());
        $this->assertTrue($this->stateMachine->isInErrorState());
        $this->assertFalse($this->stateMachine->isHandshakeCompleted());
    }

    public function testErrorStateFromAnyState(): void
    {
        $this->stateMachine->transitionToString('wait_server_hello');
        $this->stateMachine->transitionToString('error');
        $this->assertTrue($this->stateMachine->isInErrorState());

        $this->stateMachine->reset();
        $this->stateMachine->transitionToString('wait_server_hello');
        $this->stateMachine->transitionToString('wait_encrypted_extensions');
        $this->stateMachine->transitionToString('error');
        $this->assertTrue($this->stateMachine->isInErrorState());
    }

    public function testNoTransitionFromErrorState(): void
    {
        $this->stateMachine->transitionToString('error');

        $this->expectException(TLSException::class);
        $this->expectExceptionMessage('Invalid state transition from error to wait_server_hello');

        $this->stateMachine->transitionToString('wait_server_hello');
    }

    public function testReset(): void
    {
        $this->stateMachine->transitionToString('wait_server_hello');
        $this->stateMachine->transitionToString('wait_encrypted_extensions');

        $this->stateMachine->reset();

        $this->assertSame(ClientStateEnum::INITIAL, $this->stateMachine->getCurrentClientState());
        $this->assertFalse($this->stateMachine->isHandshakeCompleted());
        $this->assertFalse($this->stateMachine->isInErrorState());
    }

    public function testResetFromErrorState(): void
    {
        $this->stateMachine->transitionToString('error');
        $this->assertTrue($this->stateMachine->isInErrorState());

        $this->stateMachine->reset();

        $this->assertSame(ClientStateEnum::INITIAL, $this->stateMachine->getCurrentClientState());
        $this->assertFalse($this->stateMachine->isInErrorState());
    }

    public function testGetCurrentStateDescription(): void
    {
        $this->assertSame('Initial state, ready to start handshake', $this->stateMachine->getCurrentStateDescription());

        $this->stateMachine->transitionToString('wait_server_hello');
        $this->assertSame('Waiting for ServerHello message', $this->stateMachine->getCurrentStateDescription());

        // 按正确顺序转换到 connected
        $this->stateMachine->transitionToString('wait_encrypted_extensions');
        $this->stateMachine->transitionToString('wait_certificate');
        $this->stateMachine->transitionToString('wait_certificate_verify');
        $this->stateMachine->transitionToString('wait_finished');
        $this->stateMachine->transitionToString('connected');
        $this->assertSame('Handshake completed, connection established', $this->stateMachine->getCurrentStateDescription());

        $this->stateMachine->transitionToString('error');
        $this->assertSame('Error state, connection failed', $this->stateMachine->getCurrentStateDescription());
    }

    public function testCanSendApplicationData(): void
    {
        $this->assertFalse($this->stateMachine->canSendApplicationData());

        $this->stateMachine->transitionToString('wait_server_hello');
        $this->assertFalse($this->stateMachine->canSendApplicationData());

        $this->stateMachine->transitionToString('wait_encrypted_extensions');
        $this->stateMachine->transitionToString('wait_certificate');
        $this->stateMachine->transitionToString('wait_certificate_verify');
        $this->stateMachine->transitionToString('wait_finished');
        $this->assertFalse($this->stateMachine->canSendApplicationData());

        $this->stateMachine->transitionToString('connected');
        $this->assertTrue($this->stateMachine->canSendApplicationData());
    }

    public function testCanReceiveApplicationData(): void
    {
        $this->assertFalse($this->stateMachine->canReceiveApplicationData());

        $this->stateMachine->transitionToString('wait_server_hello');
        $this->assertFalse($this->stateMachine->canReceiveApplicationData());

        $this->stateMachine->transitionToString('wait_encrypted_extensions');
        $this->stateMachine->transitionToString('wait_certificate');
        $this->stateMachine->transitionToString('wait_certificate_verify');
        $this->stateMachine->transitionToString('wait_finished');
        $this->assertFalse($this->stateMachine->canReceiveApplicationData());

        $this->stateMachine->transitionToString('connected');
        $this->assertTrue($this->stateMachine->canReceiveApplicationData());
    }

    public function testCompleteHandshakeFlow(): void
    {
        $states = [
            'wait_server_hello',
            'wait_encrypted_extensions',
            'wait_certificate',
            'wait_certificate_verify',
            'wait_finished',
            'connected',
        ];

        foreach ($states as $state) {
            $this->assertFalse($this->stateMachine->isHandshakeCompleted());
            $this->stateMachine->transitionToString($state);
        }

        $this->assertTrue($this->stateMachine->isHandshakeCompleted());
    }

    public function testMultipleResets(): void
    {
        $this->stateMachine->transitionToString('wait_server_hello');
        $this->stateMachine->reset();
        $this->assertSame(ClientStateEnum::INITIAL, $this->stateMachine->getCurrentClientState());

        $this->stateMachine->transitionToString('wait_server_hello');
        $this->stateMachine->transitionToString('wait_encrypted_extensions');
        $this->stateMachine->reset();
        $this->assertSame(ClientStateEnum::INITIAL, $this->stateMachine->getCurrentClientState());

        $this->stateMachine->reset();
        $this->assertSame(ClientStateEnum::INITIAL, $this->stateMachine->getCurrentClientState());
    }

    public function testStateTransitionWithCaseInsensitive(): void
    {
        // 测试状态名称的大小写敏感性
        $this->expectException(TLSException::class);
        $this->stateMachine->transitionToString('WAIT_SERVER_HELLO');
    }

    public function testTransitionTo(): void
    {
        // 需要先导入 HandshakeStateEnum
        $handshakeStateEnum = $this->stateMachine->getCurrentState();
        $this->assertInstanceOf('Tourze\TLSHandshakeFlow\StateMachine\HandshakeStateEnum', $handshakeStateEnum);

        // 由于我们无法直接创建 HandshakeStateEnum 实例（需要依赖外部包），
        // 我们测试通过 getCurrentState() 返回的状态进行 transitionTo 操作
        $currentHandshakeState = $this->stateMachine->getCurrentState();

        // 由于从 INITIAL 状态转换到 INITIAL 状态是无效的，我们期望抛出异常
        $this->expectException(TLSException::class);
        $this->expectExceptionMessage('Invalid state transition from initial to initial');

        $this->stateMachine->transitionTo($currentHandshakeState);
    }

    public function testTransitionToString(): void
    {
        // 测试基本的字符串状态转换
        $this->stateMachine->transitionToString('wait_server_hello');
        $this->assertSame(ClientStateEnum::WAIT_SERVER_HELLO, $this->stateMachine->getCurrentClientState());

        // 测试连续转换
        $this->stateMachine->transitionToString('wait_encrypted_extensions');
        $this->assertSame(ClientStateEnum::WAIT_ENCRYPTED_EXTENSIONS, $this->stateMachine->getCurrentClientState());

        // 测试转换到错误状态
        $this->stateMachine->transitionToString('error');
        $this->assertSame(ClientStateEnum::ERROR, $this->stateMachine->getCurrentClientState());
        $this->assertTrue($this->stateMachine->isInErrorState());
    }

    public function testTransitionToInvalidState(): void
    {
        $this->expectException(TLSException::class);
        $this->expectExceptionMessage('Invalid state transition to: invalid_state');

        $this->stateMachine->transitionToString('invalid_state');
    }

    public function testTransitionToSkipStates(): void
    {
        // 测试跳过状态的无效转换
        $this->expectException(TLSException::class);
        $this->expectExceptionMessage('Invalid state transition from initial to wait_encrypted_extensions');

        $this->stateMachine->transitionToString('wait_encrypted_extensions');
    }
}
