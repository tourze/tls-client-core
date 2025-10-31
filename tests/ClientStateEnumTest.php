<?php

declare(strict_types=1);

namespace Tourze\TLSClientCore\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitEnum\AbstractEnumTestCase;
use Tourze\TLSClientCore\ClientStateEnum;

/**
 * ClientStateEnum测试
 *
 * @internal
 */
#[CoversClass(ClientStateEnum::class)]
final class ClientStateEnumTest extends AbstractEnumTestCase
{
    public function testAllStatesExist(): void
    {
        $expectedStates = [
            'INITIAL',
            'WAIT_SERVER_HELLO',
            'WAIT_ENCRYPTED_EXTENSIONS',
            'WAIT_CERTIFICATE',
            'WAIT_CERTIFICATE_VERIFY',
            'WAIT_FINISHED',
            'CONNECTED',
            'ERROR',
        ];

        foreach ($expectedStates as $state) {
            $this->assertTrue(defined('Tourze\TLSClientCore\ClientStateEnum::' . $state));
        }
    }

    public function testStateValues(): void
    {
        $this->assertSame('initial', ClientStateEnum::INITIAL->value);
        $this->assertSame('wait_server_hello', ClientStateEnum::WAIT_SERVER_HELLO->value);
        $this->assertSame('wait_encrypted_extensions', ClientStateEnum::WAIT_ENCRYPTED_EXTENSIONS->value);
        $this->assertSame('wait_certificate', ClientStateEnum::WAIT_CERTIFICATE->value);
        $this->assertSame('wait_certificate_verify', ClientStateEnum::WAIT_CERTIFICATE_VERIFY->value);
        $this->assertSame('wait_finished', ClientStateEnum::WAIT_FINISHED->value);
        $this->assertSame('connected', ClientStateEnum::CONNECTED->value);
        $this->assertSame('error', ClientStateEnum::ERROR->value);
    }

    public function testGetDisplayName(): void
    {
        $this->assertSame('Initial', ClientStateEnum::INITIAL->getDisplayName());
        $this->assertSame('Wait Server Hello', ClientStateEnum::WAIT_SERVER_HELLO->getDisplayName());
        $this->assertSame('Wait Encrypted Extensions', ClientStateEnum::WAIT_ENCRYPTED_EXTENSIONS->getDisplayName());
        $this->assertSame('Wait Certificate', ClientStateEnum::WAIT_CERTIFICATE->getDisplayName());
        $this->assertSame('Wait Certificate Verify', ClientStateEnum::WAIT_CERTIFICATE_VERIFY->getDisplayName());
        $this->assertSame('Wait Finished', ClientStateEnum::WAIT_FINISHED->getDisplayName());
        $this->assertSame('Connected', ClientStateEnum::CONNECTED->getDisplayName());
        $this->assertSame('Error', ClientStateEnum::ERROR->getDisplayName());
    }

    public function testIsWaitingState(): void
    {
        $this->assertFalse(ClientStateEnum::INITIAL->isWaitingState());
        $this->assertTrue(ClientStateEnum::WAIT_SERVER_HELLO->isWaitingState());
        $this->assertTrue(ClientStateEnum::WAIT_ENCRYPTED_EXTENSIONS->isWaitingState());
        $this->assertTrue(ClientStateEnum::WAIT_CERTIFICATE->isWaitingState());
        $this->assertTrue(ClientStateEnum::WAIT_CERTIFICATE_VERIFY->isWaitingState());
        $this->assertTrue(ClientStateEnum::WAIT_FINISHED->isWaitingState());
        $this->assertFalse(ClientStateEnum::CONNECTED->isWaitingState());
        $this->assertFalse(ClientStateEnum::ERROR->isWaitingState());
    }

    public function testIsTerminalState(): void
    {
        $this->assertFalse(ClientStateEnum::INITIAL->isTerminalState());
        $this->assertFalse(ClientStateEnum::WAIT_SERVER_HELLO->isTerminalState());
        $this->assertFalse(ClientStateEnum::WAIT_ENCRYPTED_EXTENSIONS->isTerminalState());
        $this->assertFalse(ClientStateEnum::WAIT_CERTIFICATE->isTerminalState());
        $this->assertFalse(ClientStateEnum::WAIT_CERTIFICATE_VERIFY->isTerminalState());
        $this->assertFalse(ClientStateEnum::WAIT_FINISHED->isTerminalState());
        $this->assertTrue(ClientStateEnum::CONNECTED->isTerminalState());
        $this->assertTrue(ClientStateEnum::ERROR->isTerminalState());
    }

    public function testGetNextExpectedState(): void
    {
        $this->assertSame(ClientStateEnum::WAIT_SERVER_HELLO, ClientStateEnum::INITIAL->getNextExpectedState());
        $this->assertSame(ClientStateEnum::WAIT_ENCRYPTED_EXTENSIONS, ClientStateEnum::WAIT_SERVER_HELLO->getNextExpectedState());
        $this->assertSame(ClientStateEnum::WAIT_CERTIFICATE, ClientStateEnum::WAIT_ENCRYPTED_EXTENSIONS->getNextExpectedState());
        $this->assertSame(ClientStateEnum::WAIT_CERTIFICATE_VERIFY, ClientStateEnum::WAIT_CERTIFICATE->getNextExpectedState());
        $this->assertSame(ClientStateEnum::WAIT_FINISHED, ClientStateEnum::WAIT_CERTIFICATE_VERIFY->getNextExpectedState());
        $this->assertSame(ClientStateEnum::CONNECTED, ClientStateEnum::WAIT_FINISHED->getNextExpectedState());
        $this->assertNull(ClientStateEnum::CONNECTED->getNextExpectedState());
        $this->assertNull(ClientStateEnum::ERROR->getNextExpectedState());
    }

    public function testTryFromValidValues(): void
    {
        $this->assertSame(ClientStateEnum::INITIAL, ClientStateEnum::tryFrom('initial'));
        $this->assertSame(ClientStateEnum::WAIT_SERVER_HELLO, ClientStateEnum::tryFrom('wait_server_hello'));
        $this->assertSame(ClientStateEnum::CONNECTED, ClientStateEnum::tryFrom('connected'));
        $this->assertSame(ClientStateEnum::ERROR, ClientStateEnum::tryFrom('error'));
    }

    public function testTryFromInvalidValues(): void
    {
        $this->assertNull(ClientStateEnum::tryFrom('invalid'));
        $this->assertNull(ClientStateEnum::tryFrom(''));
        $this->assertNull(ClientStateEnum::tryFrom('INITIAL'));
        $this->assertNull(ClientStateEnum::tryFrom('wait_invalid'));
    }

    public function testFromValidValues(): void
    {
        $this->assertSame(ClientStateEnum::INITIAL, ClientStateEnum::from('initial'));
        $this->assertSame(ClientStateEnum::WAIT_SERVER_HELLO, ClientStateEnum::from('wait_server_hello'));
        $this->assertSame(ClientStateEnum::CONNECTED, ClientStateEnum::from('connected'));
        $this->assertSame(ClientStateEnum::ERROR, ClientStateEnum::from('error'));
    }

    public function testFromInvalidValue(): void
    {
        $this->expectException(\ValueError::class);
        ClientStateEnum::from('invalid');
    }

    public function testCases(): void
    {
        $cases = ClientStateEnum::cases();
        $this->assertCount(8, $cases);

        $values = array_map(fn ($case) => $case->value, $cases);
        $this->assertContains('initial', $values);
        $this->assertContains('wait_server_hello', $values);
        $this->assertContains('wait_encrypted_extensions', $values);
        $this->assertContains('wait_certificate', $values);
        $this->assertContains('wait_certificate_verify', $values);
        $this->assertContains('wait_finished', $values);
        $this->assertContains('connected', $values);
        $this->assertContains('error', $values);
    }

    public function testStateProgression(): void
    {
        $progression = [
            ClientStateEnum::INITIAL,
            ClientStateEnum::WAIT_SERVER_HELLO,
            ClientStateEnum::WAIT_ENCRYPTED_EXTENSIONS,
            ClientStateEnum::WAIT_CERTIFICATE,
            ClientStateEnum::WAIT_CERTIFICATE_VERIFY,
            ClientStateEnum::WAIT_FINISHED,
            ClientStateEnum::CONNECTED,
        ];

        for ($i = 0; $i < count($progression) - 1; ++$i) {
            $current = $progression[$i];
            $expected = $progression[$i + 1];
            $this->assertSame($expected, $current->getNextExpectedState());
        }
    }

    public function testWaitingStatesClassification(): void
    {
        $waitingStates = array_filter(
            ClientStateEnum::cases(),
            fn ($state) => $state->isWaitingState()
        );

        $this->assertCount(5, $waitingStates);

        $waitingStateValues = array_map(fn ($state) => $state->value, $waitingStates);
        $this->assertContains('wait_server_hello', $waitingStateValues);
        $this->assertContains('wait_encrypted_extensions', $waitingStateValues);
        $this->assertContains('wait_certificate', $waitingStateValues);
        $this->assertContains('wait_certificate_verify', $waitingStateValues);
        $this->assertContains('wait_finished', $waitingStateValues);
    }

    public function testTerminalStatesClassification(): void
    {
        $terminalStates = array_filter(
            ClientStateEnum::cases(),
            fn ($state) => $state->isTerminalState()
        );

        $this->assertCount(2, $terminalStates);

        $terminalStateValues = array_map(fn ($state) => $state->value, $terminalStates);
        $this->assertContains('connected', $terminalStateValues);
        $this->assertContains('error', $terminalStateValues);
    }

    public function testToArray(): void
    {
        $array = ClientStateEnum::INITIAL->toArray();

        $this->assertIsArray($array);
        $this->assertCount(2, $array);
        $this->assertArrayHasKey('value', $array);
        $this->assertArrayHasKey('label', $array);
        $this->assertSame('initial', $array['value']);
        $this->assertSame('Initial', $array['label']);

        // 测试其他状态
        $waitArray = ClientStateEnum::WAIT_SERVER_HELLO->toArray();
        $this->assertSame('wait_server_hello', $waitArray['value']);
        $this->assertSame('Wait Server Hello', $waitArray['label']);

        $connectedArray = ClientStateEnum::CONNECTED->toArray();
        $this->assertSame('connected', $connectedArray['value']);
        $this->assertSame('Connected', $connectedArray['label']);
    }
}
