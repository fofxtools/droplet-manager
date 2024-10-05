<?php

namespace FOfX\DropletManager\Tests;

use FOfX\DropletManager\DropletManager;
use PHPUnit\Framework\TestCase;
use phpseclib3\Net\SSH2;
use FOfX\DropletManager\CyberApi;
use DigitalOceanV2\Client as DigitalOceanClient;
use DigitalOceanV2\Api\Droplet;

/**
 * Unit tests for the DropletManager class.
 */
class DropletManagerTest extends TestCase
{
    private $dropletManager;
    private $mockConfig;
    private $mockClient;
    private $mockDropletApi;

    /**
     * Setup the DropletManager instance with a mock configuration before each test.
     */
    protected function setUp(): void
    {
        // Mock the DigitalOceanClient and Droplet API
        $this->mockClient     = $this->createMock(DigitalOceanClient::class);
        $this->mockDropletApi = $this->createMock(Droplet::class);

        // Configure the mock client to return the mock Droplet API
        $this->mockClient->method('droplet')->willReturn($this->mockDropletApi);

        // Mock configuration for DigitalOcean and droplet-specific settings
        $this->mockConfig = [
            'digitalocean' => [
                'token'    => 'mock-token',
                'image_id' => 'mock-image-id',
            ],
            'test-droplet' => [
                'server_ip'           => '127.0.0.1',
                'root_password'       => 'root123',
                'mysql_root_password' => 'mysql123',
                'port'                => '8090',
                'admin'               => 'admin',
                'password'            => 'admin123',
            ],
        ];

        // Create a DropletManager instance with the mocked client and configuration
        $this->dropletManager = new DropletManager($this->mockConfig, 'test-droplet', $this->mockClient);
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

    public function testCreateDropletSuccess()
    {
        // Simulate droplet creation and status polling
        $createdDroplet = (object) ['id' => 12345];
        $dropletInfo    = (object) [
            'status'   => 'active',
            'name'     => 'test-droplet',
            'networks' => [(object) ['ipAddress' => '192.168.1.1']],
        ];

        $this->mockDropletApi->method('create')->willReturn($createdDroplet);
        $this->mockDropletApi->method('getById')->willReturn($dropletInfo);

        // Call createDroplet and expect the IP address to be returned
        $ipAddress = $this->dropletManager->createDroplet('test-droplet', 'nyc3', 's-1vcpu-1gb');

        // Check if the IP address is correct
        $this->assertEquals('192.168.1.1', $ipAddress);
    }

    public function testCreateDropletTimeout()
    {
        // Simulate droplet creation and timeout (droplet never becomes active)
        $createdDroplet = (object) ['id' => 12345];
        $dropletInfo    = (object) ['status' => 'new'];  // Droplet status never becomes 'active'

        $this->mockDropletApi->method('create')->willReturn($createdDroplet);
        $this->mockDropletApi->method('getById')->willReturnOnConsecutiveCalls(...array_fill(0, 35, $dropletInfo));

        // Call createDroplet with a very short sleep duration
        $ipAddress = $this->dropletManager->createDroplet('test-droplet', 'nyc3', 's-1vcpu-1gb', 0.001);

        // Expect null because of timeout
        $this->assertNull($ipAddress);
    }
}
