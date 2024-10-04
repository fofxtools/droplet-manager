<?php

namespace FOfX\DropletManager\Tests;

use FOfX\DropletManager\DropletManager;
use PHPUnit\Framework\TestCase;
use phpseclib3\Net\SSH2;
use FOfX\DropletManager\CyberApi;

/**
 * Unit tests for the DropletManager class.
 */
class DropletManagerTest extends TestCase
{
    private $dropletManager;
    private $mockConfig;

    /**
     * Setup the DropletManager instance with a mock configuration before each test.
     */
    protected function setUp(): void
    {
        // Mock configuration for a droplet
        $this->mockConfig = [
            'test-droplet' => [
                'server_ip'           => '127.0.0.1',
                'root_password'       => 'root123',
                'mysql_root_password' => 'mysql123',
                'port'                => '8090',
                'admin'               => 'admin',
                'password'            => 'admin123',
            ],
        ];

        // Create a DropletManager instance with the mock config
        $this->dropletManager = new DropletManager($this->mockConfig, 'test-droplet');
    }

    /**
     * Test setting and getting the droplet name.
     */
    public function testSetAndGetDropletName(): void
    {
        $this->dropletManager->setDropletName('new-droplet');
        $this->assertSame('new-droplet', $this->dropletManager->getDropletName());
    }

    /**
     * Test that verifyConnectionSsh() establishes a successful SSH connection.
     */
    public function testVerifyConnectionSshSuccess(): void
    {
        // Mock the SSH2 class and its login method
        $mockSsh = $this->createMock(SSH2::class);
        $mockSsh->method('login')
            ->willReturn(true);

        // Inject the mock SSH connection using reflection
        $reflection    = new \ReflectionClass($this->dropletManager);
        $sshConnection = $reflection->getProperty('sshConnection');
        $sshConnection->setAccessible(true);
        $sshConnection->setValue($this->dropletManager, $mockSsh);

        // Test the successful SSH connection
        $this->assertTrue($this->dropletManager->verifyConnectionSsh());
    }

    /**
     * Test that verifyConnectionSsh() throws an exception on failed login.
     */
    public function testVerifyConnectionSshFailsLogin(): void
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Login failed.');

        // Mock the SSH2 class and simulate login failure
        $mockSsh = $this->createMock(SSH2::class);
        $mockSsh->method('login')
            ->willReturn(false);

        // Inject the mock SSH connection using reflection
        $reflection    = new \ReflectionClass($this->dropletManager);
        $sshConnection = $reflection->getProperty('sshConnection');
        $sshConnection->setAccessible(true);
        $sshConnection->setValue($this->dropletManager, $mockSsh);

        // Test the SSH connection failure
        $this->dropletManager->verifyConnectionSsh();
    }

    /**
     * Test that verifyConnectionSsh() throws an exception if droplet config is missing.
     */
    public function testVerifyConnectionSshThrowsConfigException(): void
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Configuration for droplet non-existent-droplet not found.');

        // Set a non-existent droplet
        $this->dropletManager->setDropletName('non-existent-droplet');

        // Test the missing droplet configuration
        $this->dropletManager->verifyConnectionSsh();
    }

    /**
     * Test that verifyConnectionCyberApi() establishes a successful API connection.
     */
    public function testVerifyConnectionCyberApiSuccess(): void
    {
        // Mock the CyberApi class and its verify_connection method
        $mockCyberApi = $this->createMock(CyberApi::class);
        $mockCyberApi->method('verify_connection')
            ->willReturn(['verifyConn' => true]);

        // Inject the mock CyberApi instance using reflection
        $reflection       = new \ReflectionClass($this->dropletManager);
        $cyberApiProperty = $reflection->getProperty('cyberApi');
        $cyberApiProperty->setAccessible(true);
        $cyberApiProperty->setValue($this->dropletManager, $mockCyberApi);

        // Test the successful API connection
        $this->assertTrue($this->dropletManager->verifyConnectionCyberApi());
    }

    /**
     * Test that verifyConnectionCyberApi() returns false on failed API connection.
     */
    public function testVerifyConnectionCyberApiFailsLogin(): void
    {
        // Mock the CyberApi class and simulate a failed connection
        $mockCyberApi = $this->createMock(CyberApi::class);
        $mockCyberApi->method('verify_connection')
            ->willReturn(['verifyConn' => false]);

        // Inject the mock CyberApi instance using reflection
        $reflection       = new \ReflectionClass($this->dropletManager);
        $cyberApiProperty = $reflection->getProperty('cyberApi');
        $cyberApiProperty->setAccessible(true);
        $cyberApiProperty->setValue($this->dropletManager, $mockCyberApi);

        // Test the API connection failure
        $this->assertFalse($this->dropletManager->verifyConnectionCyberApi());
    }

    /**
     * Test that verifyConnectionCyberApi() returns false if an exception is thrown.
     */
    public function testVerifyConnectionCyberApiThrowsException(): void
    {
        // Mock the CyberApi class and simulate an exception
        $mockCyberApi = $this->createMock(CyberApi::class);
        $mockCyberApi->method('verify_connection')
            ->willThrowException(new \Exception('API connection failed'));

        // Inject the mock CyberApi instance using reflection
        $reflection       = new \ReflectionClass($this->dropletManager);
        $cyberApiProperty = $reflection->getProperty('cyberApi');
        $cyberApiProperty->setAccessible(true);
        $cyberApiProperty->setValue($this->dropletManager, $mockCyberApi);

        // Test that the exception is handled and false is returned
        $this->assertFalse($this->dropletManager->verifyConnectionCyberApi());
    }

    /**
     * Test that verifyConnectionCyberApi() returns false when the droplet config is missing.
     */
    public function testVerifyConnectionCyberApiReturnsFalseWhenConfigMissing(): void
    {
        // Set a non-existent droplet
        $this->dropletManager->setDropletName('non-existent-droplet');

        // Assert that verifyConnectionCyberApi() returns false
        $this->assertFalse($this->dropletManager->verifyConnectionCyberApi());
    }
}
