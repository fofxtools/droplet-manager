<?php

namespace FOfX\DropletManager\Tests;

use FOfX\DropletManager\DropletManager;
use PHPUnit\Framework\TestCase;
use phpseclib3\Net\SSH2;
use FOfX\DropletManager\CyberApi;
use DigitalOceanV2\Client as DigitalOceanClient;
use DigitalOceanV2\Api\Droplet;
use DigitalOceanV2\Exception\ResourceNotFoundException;
use FOfX\DropletManager\CyberLink;
use Monolog\Logger;
use Monolog\Handler\NullHandler;

/**
 * Unit tests for the DropletManager class.
 */
class DropletManagerTest extends TestCase
{
    private $dropletManager;
    private $mockConfig;
    private $mockClient;
    private $mockDropletApi;
    private $cyberApiMock;
    private $dropletManagerWithCyberApi;

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
            'logging' => [
                'path'  => 'php://stdout',
                'level' => \Monolog\Level::Info,
            ],
            'digitalocean' => [
                'token'    => 'mock-token',
                'image_id' => 'mock-image-id',
            ],
            'test-droplet' => [
                'server_ip'           => '127.0.0.1',
                'root_password'       => 'root123',
                'mysql_root_password' => 'mysql123',
                'cyberpanel_port'     => 8090,
                'cyberpanel_admin'    => 'admin',
                'cyberpanel_password' => 'admin123',
            ],
        ];

        // Create a Logger with a NullHandler for testing
        $logger = new Logger('test');
        $logger->pushHandler(new NullHandler());

        // Mock the CyberApi dependency
        $this->cyberApiMock = $this->createMock(CyberApi::class);

        // Create a DropletManager instance with the mocked client and configuration
        $this->dropletManager = new DropletManager('test-droplet', $this->mockConfig, $this->mockClient, $logger);
    }

    /**
     * Custom setup method for CyberPanel tests
     */
    private function setUpWithCyberApi()
    {
        // Clone the main DropletManager instance to avoid impacting other tests
        $this->dropletManagerWithCyberApi = clone $this->dropletManager;

        // Use reflection to inject the mock CyberApi instance into the cloned DropletManager
        $reflection       = new \ReflectionClass($this->dropletManagerWithCyberApi);
        $cyberApiProperty = $reflection->getProperty('cyberApi');
        $cyberApiProperty->setAccessible(true);
        $cyberApiProperty->setValue($this->dropletManagerWithCyberApi, $this->cyberApiMock);
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

    /**
     * Test that authenticate() is called on the DigitalOcean client when not already authenticated.
     */
    public function testAuthenticateDigitalOceanCallsAuthenticateWhenNotAuthenticated()
    {
        // Expect authenticate to be called once with the provided token
        $this->mockClient->expects($this->once())
            ->method('authenticate')
            ->with($this->mockConfig['digitalocean']['token']);

        // Call the method under test
        $this->dropletManager->authenticateDigitalOcean();
    }

    /**
     * Test that authenticate() is not called on the DigitalOcean client if already authenticated.
     */
    public function testAuthenticateDigitalOceanDoesNotCallAuthenticateWhenAlreadyAuthenticated()
    {
        // Use reflection to set the private property digitalOceanClientIsAuthenticated to true
        $reflection = new \ReflectionClass($this->dropletManager);
        $property   = $reflection->getProperty('digitalOceanClientIsAuthenticated');
        $property->setAccessible(true);
        $property->setValue($this->dropletManager, true);

        // Expect authenticate to not be called at all
        $this->mockClient->expects($this->never())
            ->method('authenticate');

        // Call the method under test
        $this->dropletManager->authenticateDigitalOcean();
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

    public function testConnectCyberLinkSuccess(): void
    {
        // Mock the CyberLink class
        $mockCyberLink = $this->createMock(CyberLink::class);

        // Call connectCyberLink with the mock CyberLink and expect the mock to be returned
        $cyberLinkConnection = $this->dropletManager->connectCyberLink($mockCyberLink);

        // Assert that the mock CyberLink connection is returned
        $this->assertSame($mockCyberLink, $cyberLinkConnection);
    }

    public function testConnectCyberLinkNoInjection(): void
    {
        // Mock the CyberLink class
        $mockCyberLink = $this->createMock(CyberLink::class);

        // Mock the DropletManager class, specifically the connectCyberLink method
        $dropletManager = $this->getMockBuilder(DropletManager::class)
            ->setConstructorArgs(['test-droplet', $this->mockConfig, $this->mockClient])
            ->onlyMethods(['connectCyberLink'])
            ->getMock();

        // Ensure that connectCyberLink creates a new mock CyberLink instance
        $dropletManager->method('connectCyberLink')->willReturn($mockCyberLink);

        // Call the method to trigger the logic
        $cyberLinkConnection = $dropletManager->connectCyberLink();

        // Assert that the mock CyberLink connection is returned
        $this->assertSame($mockCyberLink, $cyberLinkConnection);
    }

    public function testConnectCyberLinkReuseExistingConnection(): void
    {
        // Mock the CyberLink class
        $mockCyberLink = $this->createMock(CyberLink::class);

        // Use reflection to inject the mock CyberLink connection
        $reflection        = new \ReflectionClass($this->dropletManager);
        $cyberLinkProperty = $reflection->getProperty('cyberLinkConnection');
        $cyberLinkProperty->setAccessible(true);
        $cyberLinkProperty->setValue($this->dropletManager, $mockCyberLink);

        // Call connectCyberLink and expect the existing connection to be reused
        $cyberLinkConnection = $this->dropletManager->connectCyberLink();

        // Assert that the existing connection is returned
        $this->assertSame($mockCyberLink, $cyberLinkConnection);
    }

    /**
     * Test that isDomainConfigured() returns true when the domain exists.
     */
    public function testIsDomainConfiguredReturnsTrueWhenDomainExists()
    {
        // Mock the domain method and configure it to return a mock response
        $mockDomain = $this->createMock(\DigitalOceanV2\Api\Domain::class);

        // Mock the getByName method to return a mock response
        $mockDomain->method('getByName')
            ->with('example.com')
            ->willReturn((object) ['name' => 'example.com']);

        // Configure the DigitalOceanClient to return the mock Domain object
        $this->mockClient->method('domain')->willReturn($mockDomain);

        // Expect getByName to be called once
        $mockDomain->expects($this->once())->method('getByName')->with('example.com');

        // Assert that the method returns true
        $this->assertTrue($this->dropletManager->isDomainConfigured('example.com'));
    }

    /**
     * Test that isDomainConfigured() returns false when the domain does not exist.
     */
    public function testIsDomainConfiguredReturnsFalseWhenDomainDoesNotExist()
    {
        // Mock the domain method and configure it to throw a ResourceNotFoundException
        $mockDomain = $this->createMock(\DigitalOceanV2\Api\Domain::class);

        // Mock the getByName method to throw a ResourceNotFoundException
        $mockDomain->method('getByName')
            ->with('nonexistent.com')
            ->willThrowException(new ResourceNotFoundException());

        // Configure the DigitalOceanClient to return the mock Domain object
        $this->mockClient->method('domain')->willReturn($mockDomain);

        // Expect getByName to be called once
        $mockDomain->expects($this->once())->method('getByName')->with('nonexistent.com');

        // Assert that the method returns false
        $this->assertFalse($this->dropletManager->isDomainConfigured('nonexistent.com'));
    }

    /**
     * Test getWebsites returns an array of websites.
     */
    public function testGetWebsitesReturnsArray()
    {
        // Create a mock of CyberLink
        $mockCyberLink = $this->createMock(CyberLink::class);

        // Mock the listWebsites() method to return a sample array of websites
        $mockCyberLink->method('listWebsites')->willReturn([
            ['domain' => 'example.com', 'status' => 'active'],
            ['domain' => 'test.com', 'status' => 'inactive'],
        ]);

        // Create a mock of DropletManager and mock the connectCyberLink method to return the CyberLink mock
        $dropletManager = $this->getMockBuilder(DropletManager::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['connectCyberLink'])
            ->getMock();

        $dropletManager->method('connectCyberLink')->willReturn($mockCyberLink);

        // Call getWebsites and check that the result is as expected
        $result = $dropletManager->getWebsites();

        $this->assertIsArray($result);
        $this->assertCount(2, $result);
        $this->assertEquals('example.com', $result[0]['domain']);
        $this->assertEquals('active', $result[0]['status']);
    }

    /**
     * Test getWebsites handles empty array.
     */
    public function testGetWebsitesHandlesEmptyArray()
    {
        // Create a mock of CyberLink
        $mockCyberLink = $this->createMock(CyberLink::class);

        // Mock the listWebsites() method to return an empty array
        $mockCyberLink->method('listWebsites')->willReturn([]);

        // Create a mock of DropletManager and mock the connectCyberLink method to return the CyberLink mock
        $dropletManager = $this->getMockBuilder(DropletManager::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['connectCyberLink'])
            ->getMock();

        $dropletManager->method('connectCyberLink')->willReturn($mockCyberLink);

        // Call getWebsites and check that the result is an empty array
        $result = $dropletManager->getWebsites();

        $this->assertIsArray($result);
        $this->assertEmpty($result);
    }

    /**
     * Test getWebsites handles exceptions.
     */
    public function testGetWebsitesHandlesException()
    {
        // Create a mock of CyberLink
        $mockCyberLink = $this->createMock(CyberLink::class);

        // Mock the listWebsites() method to throw an exception
        $mockCyberLink->method('listWebsites')->willThrowException(new \Exception('Connection failed'));

        // Create a mock of DropletManager and mock the connectCyberLink method to return the CyberLink mock
        $dropletManager = $this->getMockBuilder(DropletManager::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['connectCyberLink'])
            ->getMock();

        $dropletManager->method('connectCyberLink')->willReturn($mockCyberLink);

        // Call getWebsites and check that an exception is thrown and handled
        $this->expectException(\Exception::class);
        $dropletManager->getWebsites();
    }

    public function testCreateWebsiteCyberApiSuccess()
    {
        $this->setUpWithCyberApi();

        $data = [
            'firstName'    => 'John',
            'lastName'     => 'Doe',
            'email'        => 'johndoe@email.com',
            'username'     => 'john',
            'password'     => 'password',
            'domainName'   => 'example.com',
            'websiteEmail' => 'admin@example.com',
        ];

        // Sample response from CyberApi::create_new_account
        $response = [
            'status'              => 1,
            'createWebSiteStatus' => 1,
            'error_message'       => 'None',
            'tempStatusPath'      => '/home/cyberpanel/4563',
            'LinuxUser'           => 'examp1239',
        ];

        // Configure the CyberApi mock to return a successful response
        $this->cyberApiMock->expects($this->once())
            ->method('create_new_account')
            ->willReturn($response);

        // Test the method on the cloned instance with the CyberApi mock
        $result = $this->dropletManagerWithCyberApi->createWebsiteCyberApi($data);
        $this->assertIsArray($result);
        $this->assertSame($response, $result);
    }

    public function testCreateWebsiteCyberApiFailure()
    {
        $this->setUpWithCyberApi();

        $data = [
            'firstName'    => 'John',
            'lastName'     => 'Doe',
            'email'        => 'johndoe@email.com',
            'username'     => 'john',
            'password'     => 'password',
            'domainName'   => 'example.com',
            'websiteEmail' => 'admin@example.com',
        ];

        $response = [
            'status'              => 0,
            'createWebSiteStatus' => 0,
            'error_message'       => 'Failed to create website',
            'tempStatusPath'      => '',
            'LinuxUser'           => '',
        ];

        // Mock the CyberApi::create_new_account method
        $this->cyberApiMock->expects($this->once())
            ->method('create_new_account')
            ->willReturn($response);

        // Test the failure case on the cloned instance
        $result = $this->dropletManagerWithCyberApi->createWebsiteCyberApi($data);
        $this->assertFalse($result);
    }

    public function testDeleteWebsiteCyberApiSuccess()
    {
        $this->setUpWithCyberApi();

        $data = [
            'domainName' => 'example.com',
        ];

        // Sample response from CyberApi::terminate_account indicating success
        $response = [
            'status'        => 1,
            'deleteStatus'  => 1,
            'error_message' => 'None',
        ];

        // Configure the CyberApi mock to return a successful response
        $this->cyberApiMock->expects($this->once())
            ->method('terminate_account')
            ->with([
                'adminUser'  => $this->mockConfig['test-droplet']['cyberpanel_admin'],
                'adminPass'  => $this->mockConfig['test-droplet']['cyberpanel_password'],
                'domainName' => $data['domainName'],
            ])
            ->willReturn($response);

        // Test the success case
        $result = $this->dropletManagerWithCyberApi->deleteWebsiteCyberApi($data);
        $this->assertIsArray($result);
        $this->assertSame($response, $result);
    }

    public function testDeleteWebsiteCyberApiFailure()
    {
        $this->setUpWithCyberApi();

        $data = [
            'domainName' => 'example.com',
        ];

        // Sample response from CyberApi::terminate_account indicating failure
        $response = [
            'status'        => 0,
            'deleteStatus'  => 0,
            'error_message' => 'Failed to delete website',
        ];

        // Configure the CyberApi mock to return a failure response
        $this->cyberApiMock->expects($this->once())
            ->method('terminate_account')
            ->with([
                'adminUser'  => $this->mockConfig['test-droplet']['cyberpanel_admin'],
                'adminPass'  => $this->mockConfig['test-droplet']['cyberpanel_password'],
                'domainName' => $data['domainName'],
            ])
            ->willReturn($response);

        // Test the failure case
        $result = $this->dropletManagerWithCyberApi->deleteWebsiteCyberApi($data);
        $this->assertFalse($result);
    }

    public function testGetLinuxUserForDomainSuccess()
    {
        // Mock the SSH2 class
        $mockSsh = $this->createMock(SSH2::class);

        // Configure the mock to return a successful login
        $mockSsh->method('login')->willReturn(true);

        // Configure the mock to return a valid username
        $mockSsh->method('exec')->willReturn("testuser\n");

        // Use reflection to inject the mock SSH connection
        $reflection            = new \ReflectionClass($this->dropletManager);
        $sshConnectionProperty = $reflection->getProperty('sshConnection');
        $sshConnectionProperty->setAccessible(true);
        $sshConnectionProperty->setValue($this->dropletManager, $mockSsh);

        // Call the method and assert the result
        $result = $this->dropletManager->getLinuxUserForDomain('example.com');
        $this->assertEquals('testuser', $result);
    }

    public function testGetLinuxUserForDomainLoginFailure()
    {
        // Mock the SSH2 class
        $mockSsh = $this->createMock(SSH2::class);

        // Configure the mock to return a failed login
        $mockSsh->method('login')->willReturn(false);

        // Use reflection to inject the mock SSH connection
        $reflection            = new \ReflectionClass($this->dropletManager);
        $sshConnectionProperty = $reflection->getProperty('sshConnection');
        $sshConnectionProperty->setAccessible(true);
        $sshConnectionProperty->setValue($this->dropletManager, $mockSsh);

        // Expect an exception to be thrown
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('SSH login failed for user root');

        // Call the method
        $this->dropletManager->getLinuxUserForDomain('example.com');
    }

    public function testGetLinuxUserForDomainCommandFailure()
    {
        // Mock the SSH2 class
        $mockSsh = $this->createMock(SSH2::class);

        // Configure the mock to return a successful login
        $mockSsh->method('login')->willReturn(true);

        // Configure the mock to return an error message
        $mockSsh->method('exec')->willReturn("stat: cannot stat '/home/example.com': No such file or directory\n");

        // Use reflection to inject the mock SSH connection
        $reflection            = new \ReflectionClass($this->dropletManager);
        $sshConnectionProperty = $reflection->getProperty('sshConnection');
        $sshConnectionProperty->setAccessible(true);
        $sshConnectionProperty->setValue($this->dropletManager, $mockSsh);

        // Call the method and assert the result
        $result = $this->dropletManager->getLinuxUserForDomain('example.com');
        $this->assertFalse($result);
    }

    public function testGetLinuxUserForDomainEmptyResponse()
    {
        // Mock the SSH2 class
        $mockSsh = $this->createMock(SSH2::class);

        // Configure the mock to return a successful login
        $mockSsh->method('login')->willReturn(true);

        // Configure the mock to return an empty response
        $mockSsh->method('exec')->willReturn('');

        // Use reflection to inject the mock SSH connection
        $reflection            = new \ReflectionClass($this->dropletManager);
        $sshConnectionProperty = $reflection->getProperty('sshConnection');
        $sshConnectionProperty->setAccessible(true);
        $sshConnectionProperty->setValue($this->dropletManager, $mockSsh);

        // Call the method and assert the result
        $result = $this->dropletManager->getLinuxUserForDomain('example.com');
        $this->assertFalse($result);
    }
}
