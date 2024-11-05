<?php

namespace FOfX\DropletManager\Tests;

use FOfX\DropletManager\Manager;
use PHPUnit\Framework\TestCase;
use phpseclib3\Net\SSH2;
use FOfX\DropletManager\CyberApi;
use DigitalOceanV2\Client as DigitalOceanClient;
use DigitalOceanV2\Api\Droplet;
use DigitalOceanV2\Exception\ResourceNotFoundException;
use FOfX\DropletManager\CyberLink;
use Monolog\Logger;
use Namecheap\Api as NamecheapApi;
use Namecheap\Domain\DomainsDns;
use DigitalOceanV2\Api\Domain;
use DigitalOceanV2\Api\DomainRecord;
use GuzzleHttp\Client;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use FOfX\Helper;

/**
 * Unit tests for the Manager class.
 */
class ManagerTest extends TestCase
{
    private $manager;
    private $mockConfig;
    private $mockClient;
    private $mockDropletApi;
    private $cyberApiMock;
    private $cyberLinkMock;
    private $managerWithCyberApi;
    private $managerWithCyberLink;
    private $sshMock;
    private $mockLogger;
    private $mockNamecheapApi;
    private $domainsDnsMock;
    private $managerForDnsTests;
    private $managerMock;

    /**
     * Setup the Manager instance with a mock configuration before each test.
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
            'namecheap' => [
                'username' => 'mock-username',
                'token'    => 'mock-token',
            ],
            'godaddy' => [
                'api_key'    => 'mock-api-key',
                'api_secret' => 'mock-api-secret',
            ],
        ];

        // Mock classes
        $this->mockLogger       = $this->createMock(Logger::class);
        $this->cyberApiMock     = $this->createMock(CyberApi::class);
        $this->mockNamecheapApi = $this->createMock(NamecheapApi::class);
        $this->domainsDnsMock   = $this->createMock(DomainsDns::class);

        // Create a Manager instance with the mocked client and configuration
        $this->manager = new Manager('test-droplet', $this->mockConfig, $this->mockClient, $this->mockLogger);

        // Mock the SSH2 class
        $this->sshMock = $this->createMock(SSH2::class);

        // Inject the mock SSH connection
        $this->manager->setSshConnection($this->sshMock);

        // Create a partial mock of Manager
        $this->managerMock = $this->getMockBuilder(Manager::class)
            ->setConstructorArgs(['test-droplet', $this->mockConfig, $this->mockClient, $this->mockLogger])
            ->onlyMethods([
                'configureDns',
                'getUsers',
                'getWebsites',
                'getDatabases',
                'createHtaccessForHttpsRedirect',
                'createDatabase',
                'grantRemoteDatabaseAccess',
                'setUserPasswordSsh',
                'enableSymlinksForDomain',
                'connectCyberLink',
                'restartLiteSpeed',
            ])
            ->getMock();

        // Inject the mock SSH connection into the mock Manager
        $this->managerMock->setSshConnection($this->sshMock);
    }

    /**
     * Custom setup method for CyberPanel tests
     */
    private function setUpWithCyberApi()
    {
        // Clone the main Manager instance to avoid impacting other tests
        $this->managerWithCyberApi = clone $this->manager;

        // Use reflection to inject the mock CyberApi instance into the cloned Manager
        $reflection       = new \ReflectionClass($this->managerWithCyberApi);
        $cyberApiProperty = $reflection->getProperty('cyberApi');
        $cyberApiProperty->setAccessible(true);
        $cyberApiProperty->setValue($this->managerWithCyberApi, $this->cyberApiMock);
    }

    /**
     * Custom setup method for CyberLink tests
     */
    private function setUpWithCyberLink()
    {
        // Clone the main Manager instance to avoid impacting other tests
        $this->managerWithCyberLink = clone $this->manager;

        // Create a mock CyberLink
        $this->cyberLinkMock = $this->createMock(CyberLink::class);

        // Use reflection to inject the mock CyberLink instance into the cloned Manager
        $reflection        = new \ReflectionClass($this->managerWithCyberLink);
        $cyberLinkProperty = $reflection->getProperty('cyberLinkConnection');
        $cyberLinkProperty->setAccessible(true);
        $cyberLinkProperty->setValue($this->managerWithCyberLink, $this->cyberLinkMock);

        // Configure the managerMock to return the cyberLinkMock when connectCyberLink is called
        $this->managerMock->method('connectCyberLink')
            ->willReturn($this->cyberLinkMock);
    }

    /**
     * Sets up a partial mock of the Manager class for DNS configuration tests.
     *
     * @return void
     */
    protected function setUpDnsConfigurationTests(): void
    {
        $this->managerForDnsTests = $this->getMockBuilder(Manager::class)
            ->setConstructorArgs(['test-droplet', $this->mockConfig, $this->mockClient, $this->mockLogger])
            ->onlyMethods(['isDomainConfigured'])
            ->getMock();
    }

    /**
     * Enable verbose and debug output with a real logger.
     *
     * @return void
     *
     * @phpstan-ignore-next-line
     */
    private function enableVerboseAndDebug(): void
    {
        // Create and set a real logger
        $reflection     = new \ReflectionClass($this->manager);
        $loggerProperty = $reflection->getProperty('logger');
        $loggerProperty->setAccessible(true);

        $realLogger = new \Monolog\Logger('default');
        $realLogger->pushHandler(new \Monolog\Handler\StreamHandler('php://stdout'));
        $loggerProperty->setValue($this->manager, $realLogger);

        // Enable verbose and debug modes
        $this->manager->setVerbose(true);
        $this->manager->setDebug(true);
    }

    /**
     * Disable verbose and debug output and restore mock logger.
     *
     * @return void
     *
     * @phpstan-ignore-next-line
     */
    private function disableVerboseAndDebug(): void
    {
        // Restore the mock logger
        $reflection     = new \ReflectionClass($this->manager);
        $loggerProperty = $reflection->getProperty('logger');
        $loggerProperty->setAccessible(true);
        $loggerProperty->setValue($this->manager, $this->mockLogger);

        // Disable verbose and debug modes
        $this->manager->setVerbose(false);
        $this->manager->setDebug(false);
    }

    /**
     * Test setting verbose mode to true.
     */
    public function testSetVerboseTrue(): void
    {
        $this->manager->setVerbose(true);
        $this->assertTrue($this->manager->isVerbose());
    }

    /**
     * Test setting verbose mode to false.
     */
    public function testSetVerboseFalse(): void
    {
        $this->manager->setVerbose(false);
        $this->assertFalse($this->manager->isVerbose());
    }

    /**
     * Test getting verbose mode (default value and type).
     */
    public function testIsVerbose(): void
    {
        $result = $this->manager->isVerbose();

        // Check that the return value is boolean
        $this->assertIsBool($result);
    }

    public function testSetDebugTrue(): void
    {
        $this->manager->setDebug(true);
        $this->assertTrue($this->manager->isDebug());
    }

    public function testSetDebugFalse(): void
    {
        $this->manager->setDebug(false);
        $this->assertFalse($this->manager->isDebug());
    }

    public function testIsDebug(): void
    {
        $result = $this->manager->isDebug();

        $this->assertIsBool($result);
    }

    /**
     * Test setting the droplet name.
     */
    public function testSetDropletName(): void
    {
        $this->manager->setDropletName('new-droplet');
        $reflection = new \ReflectionClass($this->manager);
        $property   = $reflection->getProperty('dropletName');
        $property->setAccessible(true);
        $this->assertSame('new-droplet', $property->getValue($this->manager));
    }

    /**
     * Test getting the droplet name.
     */
    public function testGetDropletName(): void
    {
        $reflection = new \ReflectionClass($this->manager);
        $property   = $reflection->getProperty('dropletName');
        $property->setAccessible(true);
        $property->setValue($this->manager, 'test-droplet');
        $this->assertSame('test-droplet', $this->manager->getDropletName());
    }

    /**
     * Test that setSshConnection() correctly sets the SSH connection.
     */
    public function testSetSshConnection(): void
    {
        $mockSsh = $this->createMock(SSH2::class);
        $this->manager->setSshConnection($mockSsh);

        $reflection            = new \ReflectionClass($this->manager);
        $sshConnectionProperty = $reflection->getProperty('sshConnection');
        $sshConnectionProperty->setAccessible(true);

        $this->assertSame($mockSsh, $sshConnectionProperty->getValue($this->manager));
    }

    /**
     * Test that verifyConnectionSsh() establishes a successful SSH connection.
     */
    public function testVerifyConnectionSshSuccess(): void
    {
        $this->sshMock->method('login')->willReturn(true);

        $this->assertTrue($this->manager->verifyConnectionSsh());
    }

    /**
     * Test that verifyConnectionSsh() throws an exception on failed login.
     */
    public function testVerifyConnectionSshFailsLogin(): void
    {
        $this->sshMock->method('login')->willReturn(false);

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Login failed.');

        $this->manager->verifyConnectionSsh();
    }

    /**
     * Test that verifyConnectionSsh() throws an exception if droplet config is missing.
     */
    public function testVerifyConnectionSshThrowsConfigException(): void
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Configuration for droplet non-existent-droplet not found.');

        // Set a non-existent droplet
        $this->manager->setDropletName('non-existent-droplet');

        // Test the missing droplet configuration
        $this->manager->verifyConnectionSsh();
    }

    /**
     * Test that verifyConnectionCyberApi() establishes a successful API connection.
     */
    public function testVerifyConnectionCyberApiSuccess(): void
    {
        $this->setUpWithCyberApi();

        // Configure the mock to return a successful connection response
        $this->cyberApiMock->method('verify_connection')
            ->willReturn(['verifyConn' => true]);

        // Test the successful API connection
        $this->assertTrue($this->managerWithCyberApi->verifyConnectionCyberApi());
    }

    /**
     * Test that verifyConnectionCyberApi() returns false on failed API connection.
     */
    public function testVerifyConnectionCyberApiFailsLogin(): void
    {
        $this->setUpWithCyberApi();

        // Configure the mock to return a failed connection response
        $this->cyberApiMock->method('verify_connection')
            ->willReturn(['verifyConn' => false]);

        // Test the API connection failure
        $this->assertFalse($this->managerWithCyberApi->verifyConnectionCyberApi());
    }

    /**
     * Test that verifyConnectionCyberApi() returns false if an exception is thrown.
     */
    public function testVerifyConnectionCyberApiThrowsException(): void
    {
        $this->setUpWithCyberApi();

        // Configure the mock to throw an exception
        $this->cyberApiMock->method('verify_connection')
            ->willThrowException(new \Exception('API connection failed'));

        // Test that the exception is handled and false is returned
        $this->assertFalse($this->managerWithCyberApi->verifyConnectionCyberApi());
    }

    /**
     * Test that verifyConnectionCyberApi() returns false when the droplet config is missing.
     */
    public function testVerifyConnectionCyberApiReturnsFalseWhenConfigMissing(): void
    {
        // Set a non-existent droplet
        $this->manager->setDropletName('non-existent-droplet');

        // Assert that verifyConnectionCyberApi() returns false
        $this->assertFalse($this->manager->verifyConnectionCyberApi());
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
        $this->manager->authenticateDigitalOcean();
    }

    /**
     * Test that authenticate() is not called on the DigitalOcean client if already authenticated.
     */
    public function testAuthenticateDigitalOceanDoesNotCallAuthenticateWhenAlreadyAuthenticated()
    {
        // Use reflection to set the private property digitalOceanClientIsAuthenticated to true
        $reflection = new \ReflectionClass($this->manager);
        $property   = $reflection->getProperty('digitalOceanClientIsAuthenticated');
        $property->setAccessible(true);
        $property->setValue($this->manager, true);

        // Expect authenticate to not be called at all
        $this->mockClient->expects($this->never())
            ->method('authenticate');

        // Call the method under test
        $this->manager->authenticateDigitalOcean();
    }

    public function testCreateDropletSuccess()
    {
        // Simulate droplet creation and status polling
        $createdDroplet = new \DigitalOceanV2\Entity\Droplet(['id' => 451617062]);

        $networkV4Public = new \DigitalOceanV2\Entity\Network([
            'ipAddress' => '68.183.146.101',
            'netmask'   => '255.255.240.0',
            'gateway'   => '68.183.144.1',
            'type'      => 'public',
        ]);

        $networkV4Private = new \DigitalOceanV2\Entity\Network([
            'ipAddress' => '10.108.0.2',
            'netmask'   => '255.255.240.0',
            'gateway'   => '10.108.0.1',
            'type'      => 'private',
        ]);

        $dropletInfo = new \DigitalOceanV2\Entity\Droplet([
            'id'        => 451617062,
            'name'      => 'temp-droplet',
            'status'    => 'active',
            'memory'    => 1024,
            'vcpus'     => 1,
            'disk'      => 25,
            'region'    => new \DigitalOceanV2\Entity\Region(['slug' => 'nyc3']),
            'image'     => new \DigitalOceanV2\Entity\Image(['slug' => 'litespeedtechnol-cyberpanel-20-04']),
            'size'      => new \DigitalOceanV2\Entity\Size(['slug' => 's-1vcpu-1gb']),
            'sizeSlug'  => 's-1vcpu-1gb',
            'createdAt' => '2024-10-14T17:31:43Z',
            'networks'  => (object)[
                'v4' => [$networkV4Public, $networkV4Private],
                'v6' => [],
            ],
            'tags'     => [],
            'features' => ['monitoring', 'droplet_agent', 'private_networking'],
            'vpcUuid'  => '2dcddc3e-f4e3-4ec4-8397-0479d7415ec2',
            'kernel'   => null,
        ]);

        $this->mockDropletApi->method('create')->willReturn($createdDroplet);
        $this->mockDropletApi->method('getById')->willReturn($dropletInfo);

        // Call createDroplet and expect an array to be returned
        $result = $this->manager->createDroplet('temp-droplet', 'nyc3', 's-1vcpu-1gb');

        // Expected result after processing in Manager.php
        $expectedResult = [
            'id'        => 451617062,
            'name'      => 'temp-droplet',
            'status'    => 'active',
            'memory'    => 1024,
            'vcpus'     => 1,
            'disk'      => 25,
            'region'    => 'nyc3',
            'image'     => 'litespeedtechnol-cyberpanel-20-04',
            'size'      => 's-1vcpu-1gb',
            'createdAt' => '2024-10-14T17:31:43Z',
            'networks'  => [
                [
                    'ipAddress' => '68.183.146.101',
                    'type'      => 'public',
                    'netmask'   => '255.255.240.0',
                    'gateway'   => '68.183.144.1',
                ],
                [
                    'ipAddress' => '10.108.0.2',
                    'type'      => 'private',
                    'netmask'   => '255.255.240.0',
                    'gateway'   => '10.108.0.1',
                ],
            ],
            'tags'     => [],
            'features' => ['monitoring', 'droplet_agent', 'private_networking'],
            'vpcUuid'  => '2dcddc3e-f4e3-4ec4-8397-0479d7415ec2',
            'kernel'   => null,
        ];

        // Check if the result matches the expected array
        $this->assertEquals($expectedResult, $result);
    }

    public function testCreateDropletTimeout()
    {
        // Simulate droplet creation and timeout (droplet never becomes active)
        $createdDroplet = new \DigitalOceanV2\Entity\Droplet(['id' => 12345]);
        // Droplet status never becomes 'active'
        $dropletInfo = new \DigitalOceanV2\Entity\Droplet(['status' => 'new']);

        $this->mockDropletApi->method('create')->willReturn($createdDroplet);
        $this->mockDropletApi->method('getById')->willReturnOnConsecutiveCalls(...array_fill(0, 30, $dropletInfo));

        // Call createDroplet with a very short sleep duration
        $result = $this->manager->createDroplet('test-droplet', 'nyc3', 's-1vcpu-1gb', 0.001);

        // Expect null because of timeout
        $this->assertNull($result);
    }

    public function testConnectCyberLinkSuccess(): void
    {
        // Mock the CyberLink class
        $mockCyberLink = $this->createMock(CyberLink::class);

        // Call connectCyberLink with the mock CyberLink and expect the mock to be returned
        $cyberLinkConnection = $this->manager->connectCyberLink($mockCyberLink);

        // Assert that the mock CyberLink connection is returned
        $this->assertSame($mockCyberLink, $cyberLinkConnection);
    }

    public function testConnectCyberLinkNoInjection(): void
    {
        // Mock the CyberLink class
        $mockCyberLink = $this->createMock(CyberLink::class);

        // Mock the Manager class, specifically the connectCyberLink method
        $manager = $this->getMockBuilder(Manager::class)
            ->setConstructorArgs(['test-droplet', $this->mockConfig, $this->mockClient])
            ->onlyMethods(['connectCyberLink'])
            ->getMock();

        // Ensure that connectCyberLink creates a new mock CyberLink instance
        $manager->method('connectCyberLink')->willReturn($mockCyberLink);

        // Call the method to trigger the logic
        $cyberLinkConnection = $manager->connectCyberLink();

        // Assert that the mock CyberLink connection is returned
        $this->assertSame($mockCyberLink, $cyberLinkConnection);
    }

    public function testConnectCyberLinkReuseExistingConnection(): void
    {
        // Mock the CyberLink class
        $mockCyberLink = $this->createMock(CyberLink::class);

        // Use reflection to inject the mock CyberLink connection
        $reflection        = new \ReflectionClass($this->manager);
        $cyberLinkProperty = $reflection->getProperty('cyberLinkConnection');
        $cyberLinkProperty->setAccessible(true);
        $cyberLinkProperty->setValue($this->manager, $mockCyberLink);

        // Call connectCyberLink and expect the existing connection to be reused
        $cyberLinkConnection = $this->manager->connectCyberLink();

        // Assert that the existing connection is returned
        $this->assertSame($mockCyberLink, $cyberLinkConnection);
    }

    /**
     * Test that isDomainConfigured() returns true when the domain exists.
     */
    public function testIsDomainConfiguredReturnsTrueWhenDomainExists()
    {
        // Mock the domain method and configure it to return a mock response
        $mockDomain = $this->createMock(Domain::class);

        // Mock the getByName method to return a mock response
        $mockDomain->method('getByName')
            ->with('example.com')
            ->willReturn((object) ['name' => 'example.com']);

        // Configure the DigitalOceanClient to return the mock Domain object
        $this->mockClient->method('domain')->willReturn($mockDomain);

        // Expect getByName to be called once
        $mockDomain->expects($this->once())->method('getByName')->with('example.com');

        // Assert that the method returns true
        $this->assertTrue($this->manager->isDomainConfigured('example.com'));
    }

    /**
     * Test that isDomainConfigured() returns false when the domain does not exist.
     */
    public function testIsDomainConfiguredReturnsFalseWhenDomainDoesNotExist()
    {
        // Mock the domain method and configure it to throw a ResourceNotFoundException
        $mockDomain = $this->createMock(Domain::class);

        // Mock the getByName method to throw a ResourceNotFoundException
        $mockDomain->method('getByName')
            ->with('nonexistent.com')
            ->willThrowException(new ResourceNotFoundException());

        // Configure the DigitalOceanClient to return the mock Domain object
        $this->mockClient->method('domain')->willReturn($mockDomain);

        // Expect getByName to be called once
        $mockDomain->expects($this->once())->method('getByName')->with('nonexistent.com');

        // Assert that the method returns false
        $this->assertFalse($this->manager->isDomainConfigured('nonexistent.com'));
    }

    /**
     * Test getWebsites returns an array of websites.
     */
    public function testGetWebsitesReturnsArray()
    {
        $this->setUpWithCyberLink();

        // Mock the listWebsites() method for full information
        $this->cyberLinkMock->method('listWebsites')
            ->willReturnCallback(function ($namesOnly) {
                if (!$namesOnly) {
                    return [
                        ['domain' => 'example.com', 'adminEmail' => 'admin@example.com', 'ipAddress' => '123.45.67.89', 'admin' => 'admin', 'package' => 'Default', 'state' => 'Active'],
                        ['domain' => 'test.com', 'adminEmail' => 'admin@test.com', 'ipAddress' => '98.76.54.32', 'admin' => 'admin', 'package' => 'Default', 'state' => 'Active'],
                    ];
                } else {
                    return ['example.com', 'test.com'];
                }
            });

        // Test full information mode
        $result = $this->managerWithCyberLink->getWebsites(false);

        $this->assertIsArray($result);
        $this->assertCount(2, $result);
        $this->assertEquals('example.com', $result[0]['domain']);
        $this->assertEquals('Active', $result[0]['state']);
        $this->assertArrayHasKey('adminEmail', $result[0]);
    }

    public function testGetWebsitesReturnsNamesOnly()
    {
        $this->setUpWithCyberLink();

        // Mock the listWebsites() method for names-only
        $this->cyberLinkMock->method('listWebsites')
            ->with(true)
            ->willReturn(['example.com', 'test.com']);

        // Call getWebsites with namesOnly set to true
        $result = $this->managerWithCyberLink->getWebsites(true);

        $this->assertIsArray($result);
        $this->assertCount(2, $result);
        $this->assertEquals('example.com', $result[0]);
        $this->assertEquals('test.com', $result[1]);
        $this->assertIsString($result[0]);
        $this->assertIsString($result[1]);
    }

    /**
     * Test getWebsites handles empty array.
     */
    public function testGetWebsitesHandlesEmptyArray()
    {
        $this->setUpWithCyberLink();

        // Mock the listWebsites() method to return an empty array
        $this->cyberLinkMock->method('listWebsites')->willReturn([]);

        // Call getWebsites and check that the result is an empty array
        $result = $this->managerWithCyberLink->getWebsites();

        $this->assertIsArray($result);
        $this->assertEmpty($result);
    }

    /**
     * Test getWebsites handles exceptions.
     */
    public function testGetWebsitesHandlesException()
    {
        $this->setUpWithCyberLink();

        // Mock the listWebsites() method to throw an exception
        $this->cyberLinkMock->method('listWebsites')->willThrowException(new \Exception('Connection failed'));

        // Call getWebsites and check that an exception is thrown and handled
        $this->expectException(\Exception::class);
        $this->managerWithCyberLink->getWebsites();
    }

    /**
     * Test getUsers returns an array of users.
     */
    public function testGetUsersReturnsArray()
    {
        $this->setUpWithCyberLink();

        // Mock the listUsers() method to return a sample array of users
        $this->cyberLinkMock->method('listUsers')->willReturn([
            ['username' => 'user1', 'email' => 'user1@example.com'],
            ['username' => 'user2', 'email' => 'user2@example.com'],
        ]);

        // Call getUsers and check that the result is as expected
        $result = $this->managerWithCyberLink->getUsers();

        $this->assertIsArray($result);
        $this->assertCount(2, $result);
        $this->assertEquals('user1', $result[0]['username']);
        $this->assertEquals('user1@example.com', $result[0]['email']);
    }

    /**
     * Test getUsers handles empty array.
     */
    public function testGetUsersHandlesEmptyArray()
    {
        $this->setUpWithCyberLink();

        // Mock the listUsers() method to return an empty array
        $this->cyberLinkMock->method('listUsers')->willReturn([]);

        // Call getUsers and check that the result is an empty array
        $result = $this->managerWithCyberLink->getUsers();

        $this->assertIsArray($result);
        $this->assertEmpty($result);
    }

    /**
     * Test getUsers handles exceptions.
     */
    public function testGetUsersHandlesException()
    {
        $this->setUpWithCyberLink();

        // Mock the listUsers() method to throw an exception
        $this->cyberLinkMock->method('listUsers')->willThrowException(new \Exception('Connection failed'));

        // Call getUsers and check that an exception is thrown and handled
        $this->expectException(\Exception::class);
        $this->managerWithCyberLink->getUsers();
    }

    /**
     * Test getUsers with namesOnly parameter set to true.
     */
    public function testGetUsersWithNamesOnly()
    {
        $this->setUpWithCyberLink();

        // Mock the listUsers() method to return an array of usernames
        $this->cyberLinkMock->method('listUsers')->willReturn(['user1', 'user2', 'user3']);

        // Call getUsers with namesOnly set to true
        $result = $this->managerWithCyberLink->getUsers(true);

        $this->assertIsArray($result);
        $this->assertCount(3, $result);
        $this->assertEquals(['user1', 'user2', 'user3'], $result);
    }

    /**
     * Test getDatabases handles empty array.
     */
    public function testGetDatabasesHandlesEmptyArray()
    {
        $this->setUpWithCyberLink();

        $domain = 'example.com';

        // Mock the listDatabases() method to return an empty array
        $this->cyberLinkMock->method('listDatabases')
            ->with($domain, true)
            ->willReturn([]);

        // Call getDatabases and check that the result is an empty array
        $result = $this->managerWithCyberLink->getDatabases($domain);

        $this->assertIsArray($result);
        $this->assertEmpty($result);
    }

    /**
     * Test getDatabases handles exceptions.
     */
    public function testGetDatabasesHandlesException()
    {
        $this->setUpWithCyberLink();

        $domain = 'example.com';

        // Mock the listDatabases() method to throw an exception
        $this->cyberLinkMock->method('listDatabases')
            ->with($domain, true)
            ->willThrowException(new \Exception('Connection failed'));

        // Call getDatabases and check that an exception is thrown and handled
        $this->expectException(\Exception::class);
        $this->managerWithCyberLink->getDatabases($domain);
    }

    /**
     * Test getDatabases with namesOnly parameter set to false.
     */
    public function testGetDatabasesWithFullInfo()
    {
        $this->setUpWithCyberLink();

        $domain        = 'example.com';
        $mockDatabases = [
            ['id' => 1, 'dbName' => 'example_com_db1', 'dbUser' => 'user1', 'otherInfo' => 'info1'],
            ['id' => 2, 'dbName' => 'example_com_db2', 'dbUser' => 'user2', 'otherInfo' => 'info2'],
        ];

        // Mock the listDatabases() method to return full database info
        $this->cyberLinkMock->method('listDatabases')
            ->with($domain, false)
            ->willReturn($mockDatabases);

        // Call getDatabases with namesOnly set to false
        $result = $this->managerWithCyberLink->getDatabases($domain, false);

        $this->assertIsArray($result);
        $this->assertCount(2, $result);
        $this->assertArrayHasKey('id', $result[0]);
        $this->assertArrayHasKey('otherInfo', $result[0]);
        $this->assertEquals(1, $result[0]['id']);
        $this->assertEquals('info1', $result[0]['otherInfo']);
    }

    public function testConfigureDnsForNewDomain()
    {
        $this->setUpDnsConfigurationTests();

        $domainName = 'example.com';
        $serverIp   = '123.45.67.89';

        // Mock the domain and domainRecord API clients
        $mockDomainClient       = $this->createMock(Domain::class);
        $mockDomainRecordClient = $this->createMock(DomainRecord::class);

        // Configure the mock client to return the mock Domain and DomainRecord APIs
        $this->mockClient->method('domain')->willReturn($mockDomainClient);
        $this->mockClient->method('domainRecord')->willReturn($mockDomainRecordClient);

        // Set up expectations for a new domain
        $this->managerForDnsTests->expects($this->once())
            ->method('isDomainConfigured')
            ->willReturn(false);

        $mockDomainClient->expects($this->once())->method('create')->with($domainName);

        // Expect two calls to create() with different parameters
        $mockDomainRecordClient->expects($this->exactly(2))
            ->method('create')
            ->willReturnCallback(function ($domain, $type, $name, $data) use ($domainName, $serverIp) {
                static $callNumber = 0;
                $callNumber++;

                if ($callNumber === 1) {
                    $this->assertEquals($domainName, $domain);
                    $this->assertEquals('A', $type);
                    $this->assertEquals('@', $name);
                    $this->assertEquals($serverIp, $data);
                } elseif ($callNumber === 2) {
                    $this->assertEquals($domainName, $domain);
                    $this->assertEquals('CNAME', $type);
                    $this->assertEquals('www', $name);
                    $this->assertEquals('@', $data);
                }

                return new \DigitalOceanV2\Entity\DomainRecord();
            });

        // Call the method
        $this->managerForDnsTests->configureDns($domainName, $serverIp);
    }

    public function testConfigureDnsForExistingDomain()
    {
        $this->setUpDnsConfigurationTests();

        $domainName = 'example.com';
        $serverIp   = '123.45.67.89';

        // Mock the domain and domainRecord API clients
        $mockDomainClient       = $this->createMock(Domain::class);
        $mockDomainRecordClient = $this->createMock(DomainRecord::class);

        // Configure the mock client to return the mock Domain and DomainRecord APIs
        $this->mockClient->method('domain')->willReturn($mockDomainClient);
        $this->mockClient->method('domainRecord')->willReturn($mockDomainRecordClient);

        // Set up expectations for an existing domain
        $this->managerForDnsTests->expects($this->once())
            ->method('isDomainConfigured')
            ->willReturn(true);

        $mockRecords = [
            new \DigitalOceanV2\Entity\DomainRecord(['id' => 1, 'type' => 'A', 'name' => '@', 'data' => '98.76.54.32']),
            new \DigitalOceanV2\Entity\DomainRecord(['id' => 2, 'type' => 'CNAME', 'name' => 'www', 'data' => '@']),
        ];
        $mockDomainRecordClient->method('getAll')->willReturn($mockRecords);

        // Expect the A record to be updated
        $mockDomainRecordClient->expects($this->once())
            ->method('update')
            ->with($domainName, 1, '@', $serverIp);

        // Call the method
        $this->managerForDnsTests->configureDns($domainName, $serverIp);
    }

    public function testConfigureDnsForExistingDomainMissingRecords()
    {
        $this->setUpDnsConfigurationTests();

        $domainName = 'example.com';
        $serverIp   = '123.45.67.89';

        // Mock the domain and domainRecord API clients
        $mockDomainClient       = $this->createMock(Domain::class);
        $mockDomainRecordClient = $this->createMock(DomainRecord::class);

        // Configure the mock client to return the mock Domain and DomainRecord APIs
        $this->mockClient->method('domain')->willReturn($mockDomainClient);
        $this->mockClient->method('domainRecord')->willReturn($mockDomainRecordClient);

        // Set up expectations for an existing domain with missing records
        $this->managerForDnsTests->expects($this->once())
            ->method('isDomainConfigured')
            ->willReturn(true);

        $mockRecords = []; // No existing records
        $mockDomainRecordClient->method('getAll')->willReturn($mockRecords);

        // Expect both A and CNAME records to be created
        $mockDomainRecordClient->expects($this->exactly(2))
            ->method('create')
            ->willReturnCallback(function ($domain, $type, $name, $data) use ($domainName, $serverIp) {
                static $callNumber = 0;
                $callNumber++;

                if ($callNumber === 1) {
                    $this->assertEquals($domainName, $domain);
                    $this->assertEquals('A', $type);
                    $this->assertEquals('@', $name);
                    $this->assertEquals($serverIp, $data);
                } elseif ($callNumber === 2) {
                    $this->assertEquals($domainName, $domain);
                    $this->assertEquals('CNAME', $type);
                    $this->assertEquals('www', $name);
                    $this->assertEquals('@', $data);
                }

                return new \DigitalOceanV2\Entity\DomainRecord();
            });

        // Call the method
        $this->managerForDnsTests->configureDns($domainName, $serverIp);
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
        $result = $this->managerWithCyberApi->createWebsiteCyberApi($data);
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
        $result = $this->managerWithCyberApi->createWebsiteCyberApi($data);
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
        $result = $this->managerWithCyberApi->deleteWebsiteCyberApi($data);
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
        $result = $this->managerWithCyberApi->deleteWebsiteCyberApi($data);
        $this->assertFalse($result);
    }

    public function testGetLinuxUserForDomainSuccess()
    {
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->method('exec')->willReturn("testuser\n");

        $result = $this->manager->getLinuxUserForDomain('example.com');
        $this->assertEquals('testuser', $result);
    }

    public function testGetLinuxUserForDomainLoginFailure()
    {
        $this->sshMock->method('login')->willReturn(false);

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Login failed.');

        $this->manager->getLinuxUserForDomain('example.com');
    }

    public function testGetLinuxUserForDomainCommandFailure()
    {
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->method('exec')->willReturn("stat: cannot stat '/home/example.com': No such file or directory\n");

        $result = $this->manager->getLinuxUserForDomain('example.com');
        $this->assertFalse($result);
    }

    public function testGetLinuxUserForDomainEmptyResponse()
    {
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->method('exec')->willReturn('');

        $result = $this->manager->getLinuxUserForDomain('example.com');
        $this->assertFalse($result);
    }

    public function testCreateHtaccessForHttpsRedirectSuccess()
    {
        // Mock SSH connection
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->exactly(4))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                'not exists',  // Check if .htaccess exists
                '',            // Create .htaccess file
                'testuser',    // Get Linux user for domain
                ''             // Set ownership
            );

        $result = $this->manager->createHtaccessForHttpsRedirect('example.com');
        $this->assertTrue($result);
    }

    public function testCreateHtaccessForHttpsRedirectExistingFileNoOverwrite()
    {
        // Mock SSH connection
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->once())
            ->method('exec')
            ->willReturn('exists');  // Check if .htaccess exists

        $result = $this->manager->createHtaccessForHttpsRedirect('example.com', false);
        $this->assertTrue($result);
    }

    public function testCreateHtaccessForHttpsRedirectExistingFileOverwrite()
    {
        // Mock SSH connection
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->exactly(4))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                'exists',      // Check if .htaccess exists
                '',            // Create .htaccess file
                'testuser',    // Get Linux user for domain
                ''             // Set ownership
            );

        $result = $this->manager->createHtaccessForHttpsRedirect('example.com', true);
        $this->assertTrue($result);
    }

    public function testCreateHtaccessForHttpsRedirectFailure()
    {
        // Mock SSH connection
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->exactly(2))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                'not exists',  // Check if .htaccess exists
                'Error: Permission denied'  // Create .htaccess file (fails)
            );

        $result = $this->manager->createHtaccessForHttpsRedirect('example.com');
        $this->assertFalse($result);
    }

    public function testCreateHtaccessForHttpsRedirectFailureOnOwnership()
    {
        // Mock SSH connection
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->exactly(4))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                'not exists',  // Check if .htaccess exists
                '',            // Create .htaccess file
                'testuser',    // Get Linux user for domain
                'Error: Permission denied'  // Set ownership (fails)
            );

        $result = $this->manager->createHtaccessForHttpsRedirect('example.com');
        $this->assertFalse($result);
    }

    public function testCreateHtaccessForHttpsRedirectFailureOnGetLinuxUser()
    {
        // Mock SSH connection
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->exactly(3))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                'not exists',  // Check if .htaccess exists
                '',            // Create .htaccess file
                ''             // Get Linux user for domain (fails)
            );

        $result = $this->manager->createHtaccessForHttpsRedirect('example.com');
        $this->assertFalse($result);
    }

    public function testCreateDatabaseSuccess()
    {
        $this->setUpWithCyberLink();

        // Configure the mock to return true for a successful database creation
        $this->cyberLinkMock->method('createDatabase')
            ->willReturn(true);

        // Call createDatabase and check that it returns true
        $result = $this->managerWithCyberLink->createDatabase('example.com', 'testuser', 'password123');
        $this->assertTrue($result);
    }

    public function testCreateDatabaseFailure()
    {
        $this->setUpWithCyberLink();

        // Configure the mock to return false for a failed database creation
        $this->cyberLinkMock->method('createDatabase')
            ->willReturn(false);

        // Call createDatabase and check that it returns false
        $result = $this->managerWithCyberLink->createDatabase('example.com', 'testuser', 'password123');
        $this->assertFalse($result);
    }

    public function testCreateDatabaseException()
    {
        $this->setUpWithCyberLink();

        // Configure the mock to throw an exception
        $this->cyberLinkMock->method('createDatabase')
            ->willThrowException(new \Exception('Database creation failed'));

        // Call createDatabase and check that it returns false when an exception is thrown
        $result = $this->managerWithCyberLink->createDatabase('example.com', 'testuser', 'password123');
        $this->assertFalse($result);
    }

    public function testDropDatabaseSuccess()
    {
        $this->setUpWithCyberLink();

        // Configure the mock to return true for a successful database deletion
        $this->cyberLinkMock->method('deleteDatabase')
            ->willReturn(true);

        // Call dropDatabase and check that it returns true
        $result = $this->managerWithCyberLink->dropDatabase('example.com', 'testuser');
        $this->assertTrue($result);
    }

    public function testDropDatabaseFailure()
    {
        $this->setUpWithCyberLink();

        // Configure the mock to return false for a failed database deletion
        $this->cyberLinkMock->method('deleteDatabase')
            ->willReturn(false);

        // Call dropDatabase and check that it returns false
        $result = $this->managerWithCyberLink->dropDatabase('example.com', 'testuser');
        $this->assertFalse($result);
    }

    public function testDropDatabaseException()
    {
        $this->setUpWithCyberLink();

        // Configure the mock to throw an exception
        $this->cyberLinkMock->method('deleteDatabase')
            ->willThrowException(new \Exception('Database deletion failed'));

        // Call dropDatabase and check that it returns false when an exception is thrown
        $result = $this->managerWithCyberLink->dropDatabase('example.com', 'testuser');
        $this->assertFalse($result);
    }

    public function testGrantRemoteDatabaseAccessSuccess()
    {
        // Configure the SSH mock to return true for login
        $this->sshMock->method('login')->willReturn(true);

        // Set up the expectation before calling the method
        $this->sshMock->expects($this->once())
            ->method('exec')
            ->with($this->stringContains('GRANT ALL PRIVILEGES ON'))
            ->willReturn('');  // An empty string typically indicates success for MySQL commands

        // Call the method
        $result = $this->manager->grantRemoteDatabaseAccess('example.com', 'testuser', 'password123');

        // Assert that the method returns true on success
        $this->assertTrue($result);
    }

    public function testGrantRemoteDatabaseAccessFailure()
    {
        // Configure the SSH mock to return true for login
        $this->sshMock->method('login')->willReturn(true);

        // Set up the expectation before calling the method
        $this->sshMock->expects($this->once())
            ->method('exec')
            ->willThrowException(new \Exception('MySQL error'));

        // Call the method
        $result = $this->manager->grantRemoteDatabaseAccess('example.com', 'testuser', 'password123');

        // Assert that the method returns false on failure
        $this->assertFalse($result);
    }

    public function testGrantRemoteDatabaseAccessSanitizesInput()
    {
        // Configure the SSH mock to return true for login
        $this->sshMock->method('login')->willReturn(true);

        $domainName = 'example.com';
        $username   = 'test-user';
        $password   = 'pass"word';

        // Set up the expectation before calling the method
        $this->sshMock->expects($this->once())
            ->method('exec')
            ->with($this->logicalAnd(
                $this->stringContains(Helper\escapeshellarg_linux(\FOfX\Helper\sanitize_domain_for_database($domainName, $username))),
                $this->stringContains(Helper\escapeshellarg_linux($username)),
                $this->stringContains(Helper\escapeshellarg_linux($password))
            ))
            ->willReturn('');

        // Call the method with a domain name that needs sanitization
        $result = $this->manager->grantRemoteDatabaseAccess($domainName, $username, $password);

        // Assert that the method returns true
        $this->assertTrue($result);
    }

    public function testGrantRemoteDatabaseAccessVerifiesSSHConnection()
    {
        // Configure the SSH mock to fail login
        $this->sshMock->method('login')->willReturn(false);

        // Expect an exception to be thrown
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Login failed.');

        // Call the method
        $this->manager->grantRemoteDatabaseAccess('example.com', 'testuser', 'password123');
    }

    public function testSetUserPasswordSshSuccess()
    {
        // Configure mocks
        $this->sshMock->method('login')->willReturn(true);
        // Check 3 exec() calls
        $this->sshMock->expects($this->exactly(3))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                'testuser',  // getLinuxUserForDomain
                '',          // chpasswd command (success)
                'testuser P 10/09/2024 0 99999 7 -1'  // passwd -S command
            );

        // Call the method
        $result = $this->manager->setUserPasswordSsh('example.com', 'newpassword');

        // Assert
        $this->assertTrue($result);
    }

    public function testSetUserPasswordSshFailsOnSSHConnectionVerification()
    {
        // Configure mock
        $this->sshMock->method('login')->willReturn(false);

        // Expect an exception to be thrown
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Login failed.');

        // Call the method
        $this->manager->setUserPasswordSsh('example.com', 'newpassword');
    }

    public function testSetUserPasswordSshFailsOnGetLinuxUserForDomain()
    {
        // Configure mocks
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->method('exec')
            ->willReturn('');  // Empty response from getLinuxUserForDomain

        // Call the method
        $result = $this->manager->setUserPasswordSsh('example.com', 'newpassword');

        // Assert
        $this->assertFalse($result);
    }

    public function testSetUserPasswordSshFailsOnPasswordChangeCommand()
    {
        // Configure mocks
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->exactly(2))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                'testuser',  // getLinuxUserForDomain
                'chpasswd: (user testuser) pam_chauthtok() failed'  // chpasswd command (failure)
            );

        // Call the method
        $result = $this->manager->setUserPasswordSsh('example.com', 'newpassword');

        // Assert
        $this->assertFalse($result);
    }

    public function testSetUserPasswordSshSucceedsWithoutVerification()
    {
        // Configure mocks
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->exactly(2))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                'testuser',  // getLinuxUserForDomain
                ''           // chpasswd command (success)
            );

        // Call the method with verifyChange set to false
        $result = $this->manager->setUserPasswordSsh('example.com', 'newpassword', false);

        // Assert
        $this->assertTrue($result);
    }

    public function testSetUserPasswordSshSucceedsButFailsVerification()
    {
        // Configure mocks
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->exactly(3))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                'testuser',  // getLinuxUserForDomain
                '',          // chpasswd command (success)
                'testuser L 10/09/2024 0 99999 7 -1'  // passwd -S command (locked account)
            );

        // Call the method
        $result = $this->manager->setUserPasswordSsh('example.com', 'newpassword');

        // Assert
        $this->assertTrue($result);  // The method still returns true even if verification fails
    }

    public function testEnableSymlinksForDomainSuccess(): void
    {
        $domainName = 'example.com';

        // Mock the SSH connection login to return true for successful connection
        $this->sshMock->method('login')->willReturn(true);

        // Get the existing block and create replacement
        $existingBlock = 'virtualHost example.com {
        restrained 1
        other settings
    }';

        // Mock the exec method to simulate the sequence of commands
        $this->sshMock->expects($this->exactly(5))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                '',  // First grep check (symlinks not already enabled)
                'exists',  // Second grep check (original block exists)
                $existingBlock,  // Get existing block
                '',  // cp command for backup
                'updated'  // Final grep verification
            );

        // Call the method and assert that it returns true on success
        $result = $this->manager->enableSymlinksForDomain($domainName);
        $this->assertTrue($result);
    }

    public function testEnableSymlinksForDomainAlreadyEnabled(): void
    {
        $domainName = 'example.com';

        // Mock the SSH login to return true for successful connection
        $this->sshMock->method('login')->willReturn(true);

        // Mock the exec method to return 'exists' for the first check, indicating symlinks are already enabled
        $this->sshMock->expects($this->once())
            ->method('exec')
            ->willReturn('exists');

        // Call the method and assert that it returns true when symlinks are already enabled
        $result = $this->manager->enableSymlinksForDomain($domainName);
        $this->assertTrue($result);
    }

    public function testEnableSymlinksForDomainOriginalBlockNotFound(): void
    {
        $domainName = 'example.com';

        // Mock the SSH login to return true for successful connection
        $this->sshMock->method('login')->willReturn(true);

        // Mock the exec method to simulate the sequence of commands
        $this->sshMock->expects($this->exactly(2))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                '',  // First grep check (symlinks not already enabled)
                ''   // Second grep check (original block not found)
            );

        // Call the method and assert that it returns false when original block is not found
        $result = $this->manager->enableSymlinksForDomain($domainName);
        $this->assertFalse($result);
    }

    public function testEnableSymlinksForDomainVerificationFails(): void
    {
        $domainName = 'example.com';

        // Mock the SSH login to return true for successful connection
        $this->sshMock->method('login')->willReturn(true);

        // Get the existing block
        $existingBlock = 'virtualHost example.com {
        restrained 1
        other settings
    }';

        // Mock the exec method to simulate the sequence of commands
        $this->sshMock->expects($this->exactly(5))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                '',  // First grep check (symlinks not already enabled)
                'exists',  // Second grep check (original block exists)
                $existingBlock,  // Get existing block
                '',  // cp command for backup
                ''   // Final grep verification fails
            );

        // Call the method and assert that it returns false when verification fails
        $result = $this->manager->enableSymlinksForDomain($domainName);
        $this->assertFalse($result);
    }

    public function testEnableSymlinksForDomainFailsOnSSHConnectionVerification(): void
    {
        $domainName = 'example.com';

        // Mock the SSH login to return false, simulating a connection failure
        $this->sshMock->method('login')->willReturn(false);

        // Expect an exception to be thrown due to login failure
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Login failed.');

        // Call the method
        $this->manager->enableSymlinksForDomain($domainName);
    }

    public function testRestartLiteSpeedSuccess()
    {
        $this->setUpWithCyberLink();

        // Configure the mock to return a successful restart message
        $this->cyberLinkMock->method('restartLiteSpeed')
            ->willReturn('[OK] Send SIGUSR1 to 80579');

        // Call the method
        $result = $this->managerWithCyberLink->restartLiteSpeed();

        // Assert that the result matches the expected format
        $this->assertMatchesRegularExpression('/^\[OK\] Send SIGUSR1 to \d+$/', $result);
    }

    public function testRestartLiteSpeedFailure()
    {
        $this->setUpWithCyberLink();

        // Configure the mock to return an error message
        // Note: This is a hypothetical error message, adjust as needed
        $this->cyberLinkMock->method('restartLiteSpeed')
            ->willReturn('[ERROR] Failed to restart LiteSpeed');

        // Call the method
        $result = $this->managerWithCyberLink->restartLiteSpeed();

        // Assert that the result contains an error message
        $this->assertStringStartsWith('[ERROR]', $result);
    }

    public function testRestartLiteSpeedException()
    {
        $this->setUpWithCyberLink();

        // Configure the mock to throw an exception
        $this->cyberLinkMock->method('restartLiteSpeed')
            ->willThrowException(new \Exception('Connection failed'));

        // Expect an exception to be thrown
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Connection failed');

        // Call the method
        $this->managerWithCyberLink->restartLiteSpeed();
    }

    public function testUpdateNameserversNamecheapSuccess()
    {
        // Set up the expectation for logging
        $this->mockLogger->expects($this->once())
            ->method('info')
            ->with($this->stringContains('Successfully updated nameservers'));

        // Mock a successful API response
        $response = json_encode([
            'ApiResponse' => ['_Status' => 'OK'],
        ]);

        $this->domainsDnsMock->method('setCustom')
            ->with('example', 'com', 'ns1.digitalocean.com,ns2.digitalocean.com,ns3.digitalocean.com')
            ->willReturn($response);

        // Run the method with the mocked DomainsDns
        $result = $this->manager->updateNameserversNamecheap('example.com', null, false, $this->mockNamecheapApi, $this->domainsDnsMock);

        // Verify result is the expected response
        $this->assertSame($response, $result);
    }

    public function testUpdateNameserversNamecheapWithCustomNameservers()
    {
        // Set up the expectation for logging
        $this->mockLogger->expects($this->once())
            ->method('info')
            ->with($this->stringContains('Successfully updated nameservers'));

        // Mock a successful API response
        $response = json_encode([
            'ApiResponse' => ['_Status' => 'OK'],
        ]);

        $customNameservers = ['ns1.custom.com', 'ns2.custom.com'];

        $this->domainsDnsMock->method('setCustom')
            ->with('example', 'com', 'ns1.custom.com,ns2.custom.com')
            ->willReturn($response);

        // Run the method with the mocked DomainsDns and custom nameservers
        $result = $this->manager->updateNameserversNamecheap('example.com', $customNameservers, false, $this->mockNamecheapApi, $this->domainsDnsMock);

        // Verify result is the expected response
        $this->assertSame($response, $result);
    }

    public function testUpdateNameserversNamecheapApiError()
    {
        // Set up the expectation for logging
        $this->mockLogger->expects($this->once())
            ->method('error')
            ->with($this->stringContains('Error updating nameservers'));

        // Mock an error response from the API
        $response = json_encode([
            'ApiResponse' => [
                '_Status' => 'ERROR',
                'Errors'  => [
                    'Error' => ['__text' => 'Parameter Nameservers is Missing'],
                ],
            ],
        ]);

        $this->domainsDnsMock->method('setCustom')
            ->with('example', 'com', 'ns1.digitalocean.com,ns2.digitalocean.com,ns3.digitalocean.com')
            ->willReturn($response);

        // Run the method with the mocked DomainsDns
        $result = $this->manager->updateNameserversNamecheap('example.com', null, false, $this->mockNamecheapApi, $this->domainsDnsMock);

        // Verify result is the error response
        $this->assertSame($response, $result);
    }

    public function testUpdateNameserversNamecheapUsesSandbox()
    {
        // Mock a successful API response
        $response = json_encode([
            'ApiResponse' => ['_Status' => 'OK'],
        ]);

        $this->domainsDnsMock->method('setCustom')
            ->with('example', 'com', 'ns1.digitalocean.com,ns2.digitalocean.com,ns3.digitalocean.com')
            ->willReturn($response);

        // Inject the mock NamecheapApi with sandbox enabled
        $sandboxApi = $this->createMock(NamecheapApi::class);
        $sandboxApi->expects($this->once())->method('enableSandbox');

        // Run the method with the sandbox API and mocked DomainsDns
        $result = $this->manager->updateNameserversNamecheap('example.com', null, true, $sandboxApi, $this->domainsDnsMock);

        // Assert result is the expected response
        $this->assertSame($response, $result);
    }

    public function testUpdateNameserversNamecheapApiCallFailed()
    {
        // Set up the expectation for logging
        $this->mockLogger->expects($this->once())
            ->method('error')
            ->with($this->stringContains('Error updating nameservers'));

        // Mock a failed API call
        $this->domainsDnsMock->method('setCustom')
            ->with('example', 'com', 'ns1.digitalocean.com,ns2.digitalocean.com,ns3.digitalocean.com')
            ->willReturn(false);

        // Run the method with the mocked DomainsDns
        $result = $this->manager->updateNameserversNamecheap('example.com', null, false, $this->mockNamecheapApi, $this->domainsDnsMock);

        // Verify result is false
        $this->assertFalse($result);
    }

    public function testUpdateNameserversGodaddySuccess()
    {
        $domain      = 'example.com';
        $nameservers = ['ns1.example.com', 'ns2.example.com', 'ns3.example.com'];

        // Mock the Guzzle client
        $mockClient   = $this->createMock(Client::class);
        $mockResponse = $this->createMock(ResponseInterface::class);

        // Simulate a successful response
        $mockResponse->method('getStatusCode')->willReturn(200);
        $mockClient->expects($this->once())
            ->method('patch')
            ->with("/v1/domains/{$domain}", [
                'json' => [
                    'nameServers' => $nameservers,
                ],
            ])
            ->willReturn($mockResponse);

        $this->mockLogger->expects($this->once())
            ->method('info')
            ->with($this->stringContains('Nameservers updated successfully for domain example.com. Status code: 200'));

        $result = $this->manager->updateNameserversGodaddy($domain, $nameservers, $mockClient);
        $this->assertTrue($result);
    }

    public function testUpdateNameserversGodaddyClientError()
    {
        $domain      = 'example.com';
        $nameservers = ['ns1.example.com', 'ns2.example.com', 'ns3.example.com'];

        $mockClient   = $this->createMock(Client::class);
        $mockResponse = $this->createMock(ResponseInterface::class);
        $mockStream   = $this->createMock(StreamInterface::class);

        $mockStream->method('__toString')->willReturn('Not Found');
        $mockResponse->method('getStatusCode')->willReturn(404);
        $mockResponse->method('getBody')->willReturn($mockStream);

        $mockClient->expects($this->once())
            ->method('patch')
            ->willReturn($mockResponse);

        $this->mockLogger->expects($this->once())
            ->method('error')
            ->with($this->stringContains("Failed to update nameservers for domain {$domain}. Status code: 404. Response body: "));

        $result = $this->manager->updateNameserversGodaddy($domain, $nameservers, $mockClient);
        $this->assertFalse($result);
    }

    public function testUpdateNameserversGodaddyHandlesException()
    {
        $domain      = 'example.com';
        $nameservers = ['ns1.example.com', 'ns2.example.com', 'ns3.example.com'];

        $mockClient = $this->createMock(Client::class);
        $mockClient->expects($this->once())
            ->method('patch')
            ->willThrowException(new \GuzzleHttp\Exception\RequestException('Request failed', new \GuzzleHttp\Psr7\Request('PATCH', 'test')));

        $this->mockLogger->expects($this->once())
            ->method('error')
            ->with($this->stringContains("Error updating nameservers for domain {$domain}: Request failed"));

        $result = $this->manager->updateNameserversGodaddy($domain, $nameservers, $mockClient);
        $this->assertFalse($result);
    }

    public function testUpdateNameserversGodaddyMissingCredentials()
    {
        $domain      = 'example.com';
        $nameservers = ['ns1.example.com', 'ns2.example.com', 'ns3.example.com'];

        // Set up a configuration without GoDaddy credentials
        $this->mockConfig['godaddy']['api_key']    = null;
        $this->mockConfig['godaddy']['api_secret'] = null;
        $manager                                   = new Manager('test-droplet', $this->mockConfig, $this->mockClient, $this->mockLogger);

        $this->mockLogger->expects($this->once())
            ->method('error')
            ->with('GoDaddy API credentials are missing from the configuration.');

        $result = $manager->updateNameserversGodaddy($domain, $nameservers);
        $this->assertFalse($result);
    }

    public function testSetupWebsiteSuccess()
    {
        $this->setUpWithCyberLink();

        $domainName = 'example.com';
        $username   = 'testuser';
        $password   = 'testpassword';

        // Mock SSH connection
        $this->sshMock->method('login')->willReturn(true);

        // Mock CyberLink methods
        $this->cyberLinkMock->method('createUser')->willReturn(true);
        $this->cyberLinkMock->method('createWebsite')->willReturn(true);
        $this->cyberLinkMock->method('issueSSL')->willReturn(true);

        // Mock Manager methods
        $this->managerMock->expects($this->once())->method('configureDns');
        $this->managerMock->expects($this->once())->method('getUsers')->willReturn([]);
        $this->managerMock->expects($this->once())->method('getWebsites')->willReturn([]);
        $this->managerMock->expects($this->once())->method('getDatabases')->willReturn([]);
        $this->managerMock->expects($this->once())->method('createHtaccessForHttpsRedirect')->willReturn(true);
        $this->managerMock->expects($this->once())->method('createDatabase')->willReturn(true);
        $this->managerMock->expects($this->once())->method('grantRemoteDatabaseAccess')->willReturn(true);
        $this->managerMock->expects($this->once())->method('setUserPasswordSsh')->willReturn(true);
        $this->managerMock->expects($this->once())->method('enableSymlinksForDomain')->willReturn(true);

        // Expectations for logging
        $expectedLogs = [
            "Configuring DNS for {$domainName}",
            "DNS configured successfully for {$domainName}",
            "Creating user {$username}",
            "User {$username} created successfully",
            "Creating website for domain {$domainName}",
            "Website for {$domainName} created successfully",
            "Redirecting {$domainName} to HTTPS",
            "HTTPS redirection configured for {$domainName}",
            "Issuing SSL certificate for {$domainName}",
            "SSL certificate issued for {$domainName}",
            "Creating database for {$domainName}",
            "Database for {$domainName} created successfully",
            "Enabling external access to the database for {$username}",
            "External database access granted for {$username}",
            "Setting user {$username} SSH password for domain {$domainName}",
            "User {$username} SSH password set for {$domainName}",
            "Unrestraining symbolic links for {$domainName}",
            "Symbolic links unrestrained for {$domainName}",
        ];

        $this->mockLogger->expects($this->exactly(count($expectedLogs)))
            ->method('info')
            ->willReturnCallback(function ($message) use (&$expectedLogs) {
                $this->assertContains($message, $expectedLogs);
                $expectedLogs = array_diff($expectedLogs, [$message]);
            });

        // Call the method
        $this->managerMock->setupWebsite($domainName, false, 'test@example.com', 'John', 'Doe', 'john@example.com', $username, $password);

        // Assert that all expected logs were called
        $this->assertEmpty($expectedLogs, 'Not all expected logs were called');
    }

    public function testSetupWebsiteUserExists()
    {
        $this->setUpWithCyberLink();

        $domainName = 'example.com';
        $username   = 'existinguser';
        $password   = 'testpassword';

        // Mock SSH connection
        $this->sshMock->method('login')->willReturn(true);

        // Mock Manager methods
        $this->managerMock->expects($this->once())->method('configureDns');
        $this->managerMock->expects($this->once())->method('getUsers')->willReturn([$username]);
        $this->managerMock->expects($this->once())->method('getWebsites')->willReturn([]);
        $this->managerMock->expects($this->once())->method('getDatabases')->willReturn([]);
        $this->managerMock->expects($this->once())->method('createHtaccessForHttpsRedirect')->willReturn(true);
        $this->managerMock->expects($this->once())->method('createDatabase')->willReturn(true);
        $this->managerMock->expects($this->once())->method('grantRemoteDatabaseAccess')->willReturn(true);
        $this->managerMock->expects($this->once())->method('setUserPasswordSsh')->willReturn(true);
        $this->managerMock->expects($this->once())->method('enableSymlinksForDomain')->willReturn(true);

        // Mock CyberLink methods
        $this->cyberLinkMock->method('createWebsite')->willReturn(true);
        $this->cyberLinkMock->method('issueSSL')->willReturn(true);

        // Expectations for logging
        $expectedLogs = [
            "Configuring DNS for {$domainName}",
            "DNS configured successfully for {$domainName}",
            "User {$username} already exists",
            "Creating website for domain {$domainName}",
            "Website for {$domainName} created successfully",
            "Redirecting {$domainName} to HTTPS",
            "HTTPS redirection configured for {$domainName}",
            "Issuing SSL certificate for {$domainName}",
            "SSL certificate issued for {$domainName}",
            "Creating database for {$domainName}",
            "Database for {$domainName} created successfully",
            "Enabling external access to the database for {$username}",
            "External database access granted for {$username}",
            "Setting user {$username} SSH password for domain {$domainName}",
            "User {$username} SSH password set for {$domainName}",
            "Unrestraining symbolic links for {$domainName}",
            "Symbolic links unrestrained for {$domainName}",
        ];

        $this->mockLogger->expects($this->exactly(count($expectedLogs)))
            ->method('info')
            ->willReturnCallback(function ($message) use (&$expectedLogs) {
                $this->assertContains($message, $expectedLogs);
                $expectedLogs = array_diff($expectedLogs, [$message]);
            });

        // Call the method
        $this->managerMock->setupWebsite($domainName, false, 'test@example.com', 'John', 'Doe', 'john@example.com', $username, $password);

        // Assert that all expected logs were called
        $this->assertEmpty($expectedLogs, 'Not all expected logs were called');
    }

    public function testSetupWebsiteWebsiteExists()
    {
        $this->setUpWithCyberLink();

        $domainName = 'example.com';
        $username   = 'testuser';
        $password   = 'testpassword';

        // Mock SSH connection
        $this->sshMock->method('login')->willReturn(true);

        // Mock Manager methods
        $this->managerMock->expects($this->once())->method('configureDns');
        $this->managerMock->expects($this->once())->method('getUsers')->willReturn([]);
        $this->managerMock->expects($this->once())->method('getWebsites')->willReturn([$domainName]);
        $this->managerMock->expects($this->once())->method('getDatabases')->willReturn([]);
        $this->managerMock->expects($this->once())->method('createHtaccessForHttpsRedirect')->willReturn(true);
        $this->managerMock->expects($this->once())->method('createDatabase')->willReturn(true);
        $this->managerMock->expects($this->once())->method('grantRemoteDatabaseAccess')->willReturn(true);
        $this->managerMock->expects($this->once())->method('setUserPasswordSsh')->willReturn(true);
        $this->managerMock->expects($this->once())->method('enableSymlinksForDomain')->willReturn(true);

        // Mock CyberLink methods
        $this->cyberLinkMock->method('createUser')->willReturn(true);
        $this->cyberLinkMock->method('issueSSL')->willReturn(true);

        // Expectations for logging
        $expectedLogs = [
            "Configuring DNS for {$domainName}",
            "DNS configured successfully for {$domainName}",
            "Creating user {$username}",
            "User {$username} created successfully",
            "Website {$domainName} already exists",
            "Redirecting {$domainName} to HTTPS",
            "HTTPS redirection configured for {$domainName}",
            "Issuing SSL certificate for {$domainName}",
            "SSL certificate issued for {$domainName}",
            "Creating database for {$domainName}",
            "Database for {$domainName} created successfully",
            "Enabling external access to the database for {$username}",
            "External database access granted for {$username}",
            "Setting user {$username} SSH password for domain {$domainName}",
            "User {$username} SSH password set for {$domainName}",
            "Unrestraining symbolic links for {$domainName}",
            "Symbolic links unrestrained for {$domainName}",
        ];

        $this->mockLogger->expects($this->exactly(count($expectedLogs)))
            ->method('info')
            ->willReturnCallback(function ($message) use (&$expectedLogs) {
                $this->assertContains($message, $expectedLogs);
                $expectedLogs = array_diff($expectedLogs, [$message]);
            });

        // Call the method
        $this->managerMock->setupWebsite($domainName, false, 'test@example.com', 'John', 'Doe', 'john@example.com', $username, $password);

        // Assert that all expected logs were called
        $this->assertEmpty($expectedLogs, 'Not all expected logs were called');
    }

    public function testSetupWebsiteDatabaseExists()
    {
        $this->setUpWithCyberLink();

        $domainName = 'example.com';
        $username   = 'testuser';
        $password   = 'testpassword';
        $dbCount    = 1;

        // Mock SSH connection
        $this->sshMock->method('login')->willReturn(true);

        // Mock Manager methods
        $this->managerMock->expects($this->once())->method('configureDns');
        $this->managerMock->expects($this->once())->method('getUsers')->willReturn([]);
        $this->managerMock->expects($this->once())->method('getWebsites')->willReturn([]);
        $this->managerMock->expects($this->once())->method('getDatabases')->willReturn(['existing_db']);
        $this->managerMock->expects($this->once())->method('createHtaccessForHttpsRedirect')->willReturn(true);
        $this->managerMock->expects($this->once())->method('grantRemoteDatabaseAccess')->willReturn(true);
        $this->managerMock->expects($this->once())->method('setUserPasswordSsh')->willReturn(true);
        $this->managerMock->expects($this->once())->method('enableSymlinksForDomain')->willReturn(true);

        // Mock CyberLink methods
        $this->cyberLinkMock->method('createUser')->willReturn(true);
        $this->cyberLinkMock->method('createWebsite')->willReturn(true);
        $this->cyberLinkMock->method('issueSSL')->willReturn(true);

        // Expectations for logging
        $expectedLogs = [
            "Configuring DNS for {$domainName}",
            "DNS configured successfully for {$domainName}",
            "Creating user {$username}",
            "User {$username} created successfully",
            "Creating website for domain {$domainName}",
            "Website for {$domainName} created successfully",
            "Redirecting {$domainName} to HTTPS",
            "HTTPS redirection configured for {$domainName}",
            "Issuing SSL certificate for {$domainName}",
            "SSL certificate issued for {$domainName}",
            "Database(s) for {$domainName} already exist. Count: {$dbCount}.",
            "Enabling external access to the database for {$username}",
            "External database access granted for {$username}",
            "Setting user {$username} SSH password for domain {$domainName}",
            "User {$username} SSH password set for {$domainName}",
            "Unrestraining symbolic links for {$domainName}",
            "Symbolic links unrestrained for {$domainName}",
        ];

        $this->mockLogger->expects($this->exactly(count($expectedLogs)))
            ->method('info')
            ->willReturnCallback(function ($message) use (&$expectedLogs) {
                $this->assertContains($message, $expectedLogs);
                $expectedLogs = array_diff($expectedLogs, [$message]);
            });

        // Call the method
        $this->managerMock->setupWebsite($domainName, false, 'test@example.com', 'John', 'Doe', 'john@example.com', $username, $password);

        // Assert that all expected logs were called
        $this->assertEmpty($expectedLogs, 'Not all expected logs were called');
    }

    public function testSetupWebsiteFailure()
    {
        $this->setUpWithCyberLink();

        $domainName = 'example.com';
        $username   = 'testuser';
        $password   = 'testpassword';

        // Mock SSH connection
        $this->sshMock->method('login')->willReturn(true);

        // Mock Manager methods
        $this->managerMock->expects($this->once())->method('configureDns');
        $this->managerMock->expects($this->once())->method('getUsers')->willReturn([]);
        $this->managerMock->expects($this->once())->method('getWebsites')->willReturn([]);
        $this->managerMock->expects($this->once())->method('getDatabases')->willReturn([]);
        $this->managerMock->expects($this->once())->method('createHtaccessForHttpsRedirect')->willReturn(false);
        $this->managerMock->expects($this->once())->method('createDatabase')->willReturn(false);
        $this->managerMock->expects($this->once())->method('grantRemoteDatabaseAccess')->willReturn(false);
        $this->managerMock->expects($this->once())->method('setUserPasswordSsh')->willReturn(false);
        $this->managerMock->expects($this->once())->method('enableSymlinksForDomain')->willReturn(false);

        // Mock CyberLink methods
        $this->cyberLinkMock->method('createUser')->willReturn(false);
        $this->cyberLinkMock->method('createWebsite')->willReturn(false);
        $this->cyberLinkMock->method('issueSSL')->willReturn(false);

        // Expectations for logging
        $expectedErrors = [
            "Failed to create user {$username}",
            "Failed to create website for {$domainName}",
            "Failed to configure HTTPS redirection for {$domainName}",
            "Failed to issue SSL certificate for {$domainName}",
            "Failed to create database for {$domainName}",
            "Failed to grant external access to the database for {$username}",
            "Failed to set {$username} SSH password for {$domainName}",
            "Failed to unrestrain symbolic links for {$domainName}",
        ];

        $this->mockLogger->expects($this->exactly(count($expectedErrors)))
            ->method('error')
            ->willReturnCallback(function ($message) use (&$expectedErrors) {
                $this->assertContains($message, $expectedErrors);
                $expectedErrors = array_diff($expectedErrors, [$message]);
            });

        // Call the method
        $this->managerMock->setupWebsite($domainName, false, 'test@example.com', 'John', 'Doe', 'john@example.com', $username, $password);

        // Assert that all expected errors were logged
        $this->assertEmpty($expectedErrors, 'Not all expected errors were logged');
    }

    public function testDeleteWebsiteSuccess()
    {
        $this->setUpWithCyberLink();

        $domainName = 'example.com';

        // Configure the mock to return true for a successful website deletion
        $this->cyberLinkMock->method('deleteWebsite')
            ->with($domainName, false)
            ->willReturn(true);

        // Set up expectations for logging
        $expectedLogs = [
            "Deleting website for {$domainName}",
            "Website for {$domainName} deleted successfully",
        ];

        $this->mockLogger->expects($this->exactly(count($expectedLogs)))
            ->method('info')
            ->willReturnCallback(function ($message) use (&$expectedLogs) {
                $this->assertContains($message, $expectedLogs);
                $expectedLogs = array_diff($expectedLogs, [$message]);
            });

        // Call the method
        $result = $this->managerWithCyberLink->deleteWebsite($domainName);

        // Assert that the result is true
        $this->assertTrue($result);

        // Assert that all expected logs were called
        $this->assertEmpty($expectedLogs, 'Not all expected logs were called');
    }

    public function testDeleteWebsiteFailure()
    {
        $this->setUpWithCyberLink();

        $domainName = 'example.com';

        // Configure the mock to return false for a failed website deletion
        $this->cyberLinkMock->method('deleteWebsite')
            ->with($domainName, false)
            ->willReturn(false);

        // Set up expectations for logging
        $expectedLogs = [
            "Deleting website for {$domainName}"         => 'info',
            "Failed to delete website for {$domainName}" => 'error',
        ];

        foreach ($expectedLogs as $message => $method) {
            $this->mockLogger->expects($this->once())
                ->method($method)
                ->with($message);
        }

        // Call the method
        $result = $this->managerWithCyberLink->deleteWebsite($domainName);

        // Assert that the result is false
        $this->assertFalse($result);
    }

    public function testDeleteWebsiteWithDebugEnabled()
    {
        $this->setUpWithCyberLink();

        $domainName = 'example.com';

        // Configure the mock to return true for a successful website deletion with debug enabled
        $this->cyberLinkMock->method('deleteWebsite')
            ->with($domainName, true)
            ->willReturn(true);

        // Set up expectations for logging
        $expectedLogs = [
            "Deleting website for {$domainName}",
            "Website for {$domainName} deleted successfully",
        ];

        $this->mockLogger->expects($this->exactly(count($expectedLogs)))
            ->method('info')
            ->willReturnCallback(function ($message) use (&$expectedLogs) {
                $this->assertContains($message, $expectedLogs);
                $expectedLogs = array_diff($expectedLogs, [$message]);
            });

        // Call the method with debug enabled
        $result = $this->managerWithCyberLink->deleteWebsite($domainName, true);

        // Assert that the result is true
        $this->assertTrue($result);

        // Assert that all expected logs were called
        $this->assertEmpty($expectedLogs, 'Not all expected logs were called');
    }

    public function testUpdateMyCnfPasswordSuccess()
    {
        // Mock SSH connection
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->exactly(5))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                'testpass123',                    // Get password from .db_password
                'oldpass',                        // Get current password from .my.cnf
                '',                               // Backup command output (success)
                '',                               // Update command output (success)
                'testpass123'                     // Verification check passes
            );

        // Call the method
        $result = $this->manager->updateMyCnfPassword();

        // Assert
        $this->assertTrue($result);
    }

    public function testUpdateMyCnfPasswordNoUpdateNeeded()
    {
        // Mock SSH connection
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->exactly(2))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                'samepass123',                    // Get password from .db_password
                'samepass123'                     // Get current password from .my.cnf (matches)
            );

        // Call the method
        $result = $this->manager->updateMyCnfPassword();

        // Assert that no update was needed and method returns true
        $this->assertTrue($result);
    }

    public function testUpdateMyCnfPasswordFailsToGetDbPassword()
    {
        // Mock SSH connection
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->once())
            ->method('exec')
            ->willReturn('');  // Empty response when trying to get password from .db_password

        // Call the method
        $result = $this->manager->updateMyCnfPassword();

        // Assert
        $this->assertFalse($result);
    }

    public function testUpdateMyCnfPasswordFailsToGetCurrentPassword()
    {
        // Mock SSH connection
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->exactly(2))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                'testpass123',                    // Get password from .db_password
                ''                                // Empty response when trying to get current password
            );

        // Call the method
        $result = $this->manager->updateMyCnfPassword();

        // Assert
        $this->assertFalse($result);
    }

    public function testUpdateMyCnfPasswordUpdateFails()
    {
        // Mock SSH connection
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->exactly(4))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                'testpass123',                    // Get password from .db_password
                'oldpass',                        // Get current password from .my.cnf
                '',                               // Backup command output (success)
                'Permission denied'               // Update command fails
            );

        // Call the method
        $result = $this->manager->updateMyCnfPassword();

        // Assert that the update failed
        $this->assertFalse($result);
    }

    public function testUpdateMyCnfPasswordVerificationFails()
    {
        // Mock SSH connection
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->exactly(4))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                'testpass123',                    // Get password from .db_password
                'oldpass',                        // Get current password from .my.cnf
                '',                               // Update command output (success)
                'wrongpass'                       // Verification check fails
            );

        // Call the method
        $result = $this->manager->updateMyCnfPassword();

        // Assert
        $this->assertFalse($result);
    }

    public function testUpdateNanoCtrlFSearchBindingAlreadySet()
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->once())
            ->method('exec')
            ->with("grep '^bind \^F whereis all' /etc/nanorc")
            ->willReturn('bind ^F whereis all');

        $result = $this->manager->updateNanoCtrlFSearchBinding();
        $this->assertTrue($result);
    }

    public function testUpdateNanoCtrlFSearchBindingUncomment()
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->exactly(3))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                '',  // No existing binding
                '#bind ^F whereis all',  // Commented out binding
                ''   // Successful uncomment
            );

        $result = $this->manager->updateNanoCtrlFSearchBinding();
        $this->assertTrue($result);
    }

    public function testUpdateNanoCtrlFSearchBindingUncommentWithSpace()
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->exactly(3))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                '',  // No existing binding
                '# bind ^F whereis all',  // Commented out binding with space
                ''   // Successful uncomment
            );

        $result = $this->manager->updateNanoCtrlFSearchBinding();
        $this->assertTrue($result);
    }

    public function testUpdateNanoCtrlFSearchBindingUpdateExisting()
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->exactly(4))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                '',  // No existing binding
                '',  // No commented out binding
                'bind ^W whereis all',  // Different key bound
                ''   // Successful update
            );

        $result = $this->manager->updateNanoCtrlFSearchBinding();
        $this->assertTrue($result);
    }

    public function testUpdateNanoCtrlFSearchBindingAddNew()
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->exactly(4))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                '',  // No existing binding
                '',  // No commented out binding
                '',  // No other key bound
                ''   // Successful append
            );

        $result = $this->manager->updateNanoCtrlFSearchBinding();
        $this->assertTrue($result);
    }

    public function testUpdateNanoCtrlFSearchBindingFailure()
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->exactly(4))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                '',  // No existing binding
                '',  // No commented out binding
                '',  // No other key bound
                'Permission denied'  // Failed to append
            );

        $result = $this->manager->updateNanoCtrlFSearchBinding();
        $this->assertFalse($result);
    }

    public function testUpdateNanoCtrlFSearchBindingSshConnectionFailure()
    {
        // Configure the SSH mock to fail login
        $this->sshMock->method('login')->willReturn(false);

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Login failed.');

        $this->manager->updateNanoCtrlFSearchBinding();
    }

    public function testEnableCyberPanelApiAccessSuccess()
    {
        // Configure the SSH mock to return true for login
        $this->sshMock->method('login')->willReturn(true);

        // Set up the expectation for the exec method
        $this->sshMock->expects($this->once())
            ->method('exec')
            ->with($this->stringContains("UPDATE cyberpanel.loginSystem_administrator SET api = 1 WHERE userName = 'admin'"))
            ->willReturn('');  // An empty string indicates success

        // Call the method
        $result = $this->manager->enableCyberPanelApiAccess();

        // Assert that the method returns true on success
        $this->assertTrue($result);
    }

    public function testEnableCyberPanelApiAccessFailure()
    {
        // Configure the SSH mock to return true for login
        $this->sshMock->method('login')->willReturn(true);

        // Set up the expectation for the exec method
        $this->sshMock->expects($this->once())
            ->method('exec')
            ->willReturn('Error: Access denied');  // Simulate an error

        // Call the method
        $result = $this->manager->enableCyberPanelApiAccess();

        // Assert that the method returns false on failure
        $this->assertFalse($result);
    }

    public function testEnableCyberPanelApiAccessCustomUsername()
    {
        // Configure the SSH mock to return true for login
        $this->sshMock->method('login')->willReturn(true);

        // Set up the expectation for the exec method with a custom username
        $this->sshMock->expects($this->once())
            ->method('exec')
            ->with($this->stringContains("UPDATE cyberpanel.loginSystem_administrator SET api = 1 WHERE userName = 'customuser'"))
            ->willReturn('');  // An empty string indicates success

        // Call the method with a custom username
        $result = $this->manager->enableCyberPanelApiAccess('customuser');

        // Assert that the method returns true on success
        $this->assertTrue($result);
    }

    public function testEnableCyberPanelApiAccessSshConnectionFailure()
    {
        // Configure the SSH mock to return false for login
        $this->sshMock->method('login')->willReturn(false);

        // Expect an exception to be thrown
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Login failed.');

        // Call the method
        $this->manager->enableCyberPanelApiAccess();
    }

    public function testEnableCyberPanelApiAccessEscapesUsername()
    {
        // Configure the SSH mock to return true for login
        $this->sshMock->method('login')->willReturn(true);

        // Set up the expectation for the exec method with a username that needs escaping
        $this->sshMock->expects($this->once())
            ->method('exec')
            ->with($this->callback(function ($command) {
                $expectedPart         = "UPDATE cyberpanel.loginSystem_administrator SET api = 1 WHERE userName = 'user'\\''name'";
                $containsExpectedPart = strpos($command, $expectedPart) !== false;
                $this->assertTrue($containsExpectedPart, "Command does not contain expected SQL: $expectedPart");

                return $containsExpectedPart;
            }))
            ->willReturn('');  // An empty string indicates success

        // Call the method with a username that needs escaping
        $result = $this->manager->enableCyberPanelApiAccess("user'name");

        // Assert that the method returns true on success
        $this->assertTrue($result);
    }

    public function testUpdateVhostPySuccess()
    {
        // Configure the SSH mock to return true for login
        $this->sshMock->method('login')->willReturn(true);

        // Simulate the sequence of exec calls
        $this->sshMock->expects($this->exactly(5))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                '',        // grep for replacement line (not found)
                'exists',  // grep for original line (found)
                '',        // cp command for backup (success)
                '',        // sed command for replacement (success)
                'updated'  // grep for replacement line after sed (found)
            );

        // Mock the restartLiteSpeed method to return a successful message
        $this->managerMock->method('restartLiteSpeed')->willReturn('[OK] Send SIGUSR1 to 80579');

        // Inject the mock SSH connection
        $this->managerMock->setSshConnection($this->sshMock);

        // Call the method
        $result = $this->managerMock->updateVhostPy();

        // Assert that the method returns true on success
        $this->assertTrue($result);
    }

    public function testUpdateVhostPyNoChangeNeeded()
    {
        // Configure the SSH mock to return true for login
        $this->sshMock->method('login')->willReturn(true);

        // Simulate the grep command finding the replacement line already present
        $this->sshMock->expects($this->once())
            ->method('exec')
            ->willReturn('exists');  // grep for replacement line (found)

        // Inject the mock SSH connection
        $this->managerMock->setSshConnection($this->sshMock);

        // Call the method
        $result = $this->managerMock->updateVhostPy();

        // Assert that the method returns true since no changes are needed
        $this->assertTrue($result);
    }

    public function testUpdateVhostPyOriginalLineNotFound()
    {
        // Configure the SSH mock to return true for login
        $this->sshMock->method('login')->willReturn(true);

        // Simulate the grep command not finding the original line
        $this->sshMock->expects($this->exactly(2))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                '',  // grep for replacement line (not found)
                ''   // grep for original line (not found)
            );

        // Call the method
        $result = $this->manager->updateVhostPy();

        // Assert that the method returns false since the original line was not found
        $this->assertFalse($result);
    }

    public function testUpdateVhostConfsPySuccess()
    {
        // Configure the SSH mock to return true for login
        $this->sshMock->method('login')->willReturn(true);

        // Simulate the sequence of exec calls
        $this->sshMock->expects($this->exactly(5))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                '',        // grep for replacement pattern (not found)
                'exists',  // grep for original pattern (found)
                '',        // cp command for backup (success)
                '',        // sed command for replacement (success)
                'updated'  // grep for verification (found)
            );

        // Mock the restartLiteSpeed method to return a successful message
        $this->managerMock->method('restartLiteSpeed')->willReturn('[OK] Send SIGUSR1 to 80579');

        // Inject the mock SSH connection
        $this->managerMock->setSshConnection($this->sshMock);

        // Call the method
        $result = $this->managerMock->updateVhostConfsPy();

        // Assert that the method returns true on success
        $this->assertTrue($result);
    }

    public function testUpdateVhostConfsPyNoChangeNeeded()
    {
        // Configure the SSH mock to return true for login
        $this->sshMock->method('login')->willReturn(true);

        // Simulate the grep command finding the replacement pattern already present
        $this->sshMock->expects($this->once())
            ->method('exec')
            ->willReturn('exists');  // grep for replacement pattern (found)

        // Inject the mock SSH connection
        $this->managerMock->setSshConnection($this->sshMock);

        // Call the method
        $result = $this->managerMock->updateVhostConfsPy();

        // Assert that the method returns true since no changes are needed
        $this->assertTrue($result);
    }

    public function testUpdateVhostConfsPyOriginalPatternNotFound()
    {
        // Configure the SSH mock to return true for login
        $this->sshMock->method('login')->willReturn(true);

        // Simulate the grep commands not finding the patterns
        $this->sshMock->expects($this->exactly(2))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                '',  // grep for replacement pattern (not found)
                ''   // grep for original pattern (not found)
            );

        // Inject the mock SSH connection
        $this->managerMock->setSshConnection($this->sshMock);

        // Call the method
        $result = $this->managerMock->updateVhostConfsPy();

        // Assert that the method returns false since the original pattern was not found
        $this->assertFalse($result);
    }

    public function testUpdateVhostConfsPyReplacementFailed()
    {
        // Configure the SSH mock to return true for login
        $this->sshMock->method('login')->willReturn(true);

        // Simulate the sequence of exec calls with a failed sed command
        $this->sshMock->expects($this->exactly(4))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                '',        // grep for replacement pattern (not found)
                'exists',  // grep for original pattern (found)
                '',        // cp command for backup (success)
                false      // sed command for replacement (failure)
            );

        // Inject the mock SSH connection
        $this->managerMock->setSshConnection($this->sshMock);

        // Call the method
        $result = $this->managerMock->updateVhostConfsPy();

        // Assert that the method returns false on sed command failure
        $this->assertFalse($result);
    }

    public function testUpdateVhostConfsPyVerificationFailed()
    {
        // Configure the SSH mock to return true for login
        $this->sshMock->method('login')->willReturn(true);

        // Simulate the sequence of exec calls with a failed verification
        $this->sshMock->expects($this->exactly(5))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                '',        // grep for replacement pattern (not found)
                'exists',  // grep for original pattern (found)
                '',        // cp command for backup (success)
                '',        // sed command for replacement (success)
                ''         // grep for verification (not found)
            );

        // Inject the mock SSH connection
        $this->managerMock->setSshConnection($this->sshMock);

        // Call the method
        $result = $this->managerMock->updateVhostConfsPy();

        // Assert that the method returns false on verification failure
        $this->assertFalse($result);
    }

    public function testUpdateVhostConfsPyWithoutRestartingLiteSpeed()
    {
        // Configure the SSH mock to return true for login
        $this->sshMock->method('login')->willReturn(true);

        // Simulate the sequence of exec calls
        $this->sshMock->expects($this->exactly(5))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                '',        // grep for replacement pattern (not found)
                'exists',  // grep for original pattern (found)
                '',        // cp command for backup (success)
                '',        // sed command for replacement (success)
                'updated'  // grep for verification (found)
            );

        // Mock the restartLiteSpeed method and expect it not to be called
        $this->managerMock->expects($this->never())->method('restartLiteSpeed');

        // Inject the mock SSH connection
        $this->managerMock->setSshConnection($this->sshMock);

        // Call the method with restartLiteSpeed set to false
        $result = $this->managerMock->updateVhostConfsPy(false);

        // Assert that the method returns true on success
        $this->assertTrue($result);
    }

    public function testUpdateVhostConfsPySshConnectionFailure()
    {
        // Configure the SSH mock to fail login
        $this->sshMock->method('login')->willReturn(false);

        // Expect an exception to be thrown
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Login failed.');

        // Call the method
        $this->manager->updateVhostConfsPy();
    }

    public function testSetupAliasesAndFunctionsSuccess(): void
    {
        // Configure the SSH mock to return true for login
        $this->sshMock->method('login')->willReturn(true);

        // For each file check, return that it doesn't exist
        // For each creation attempt, return 'created'
        $this->sshMock->expects($this->exactly(24))  // 12 files × 2 calls each (check + create)
            ->method('exec')
            ->willReturnCallback(function ($command) {
                if (strpos($command, '[ -f ') === 0) {
                    return '';  // File doesn't exist
                }

                return 'created';  // Creation successful
            });

        $result = $this->manager->setupAliasesAndFunctions();
        $this->assertTrue($result);
    }

    public function testSetupAliasesAndFunctionsAllFilesExist(): void
    {
        // Configure the SSH mock to return true for login
        $this->sshMock->method('login')->willReturn(true);

        // For each file check, return that it exists
        $this->sshMock->expects($this->exactly(12))  // Only the existence checks
            ->method('exec')
            ->willReturn('exists');

        $result = $this->manager->setupAliasesAndFunctions();
        $this->assertTrue($result);
    }

    public function testSetupAliasesAndFunctionsMixedScenario(): void
    {
        // Configure the SSH mock to return true for login
        $this->sshMock->method('login')->willReturn(true);

        // Track number of exec calls
        $execCalls = 0;

        // Mock exec to handle all 12 files
        $this->sshMock->expects($this->any())
            ->method('exec')
            ->willReturnCallback(function ($command) use (&$execCalls) {
                $execCalls++;
                // Return 'exists' for even-numbered files, empty for odd-numbered ones
                if (strpos($command, '[ -f ') === 0) {
                    return $execCalls % 2 === 0 ? 'exists' : '';
                }

                return 'created';
            });

        $result = $this->manager->setupAliasesAndFunctions();
        $this->assertTrue($result);
        $this->assertEquals(24, $execCalls); // 12 files × 2 calls each (check + create)
    }

    public function testSetupAliasesAndFunctionsCreationFailure(): void
    {
        // Configure the SSH mock to return true for login
        $this->sshMock->method('login')->willReturn(true);

        // Track number of exec calls and creation attempts
        $execCalls        = 0;
        $creationAttempts = 0;

        $this->sshMock->expects($this->any())
            ->method('exec')
            ->willReturnCallback(function ($command) use (&$execCalls, &$creationAttempts) {
                $execCalls++;
                if (strpos($command, '[ -f ') === 0) {
                    return '';  // File doesn't exist
                }
                $creationAttempts++;

                return false;  // Creation failed
            });

        $result = $this->manager->setupAliasesAndFunctions();
        $this->assertFalse($result);
        $this->assertGreaterThan(0, $creationAttempts);
        $this->assertEquals(24, $execCalls);
    }

    /**
     * Test handling of SSH connection failure.
     */
    public function testSetupAliasesAndFunctionsSshConnectionFailure(): void
    {
        // Configure the SSH mock to fail login
        $this->sshMock->method('login')->willReturn(false);

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Login failed.');

        $this->manager->setupAliasesAndFunctions();
    }

    /**
     * Test configureScreen() when all settings are already configured correctly
     */
    public function testConfigureScreenAllSettingsAlreadyConfigured(): void
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->exactly(4))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                '',                         // Backup command success
                'exists',      // First setting already exists
                'exists', // Second setting already exists
                'exists'          // Third setting already exists
            );

        $result = $this->manager->configureScreen();
        $this->assertTrue($result);
    }

    /**
     * Test configureScreen() when all settings need to be uncommented
     */
    public function testConfigureScreenUncommentAllSettings(): void
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->exactly(13))  // 1 backup + (3 settings × 4 checks each)
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                '',                         // Backup command success
                '',                         // First setting doesn't exist (grep for uncommented)
                'exists',                   // First setting is commented (grep for commented)
                '',                         // Uncomment successful (sed command)
                'exists',                   // Verification check successful
                '',                         // Second setting doesn't exist (grep for uncommented)
                'exists',                   // Second setting is commented (grep for commented)
                '',                         // Uncomment successful (sed command)
                'exists',                   // Verification check successful
                '',                         // Third setting doesn't exist (grep for uncommented)
                'exists',                   // Third setting is commented (grep for commented)
                '',                         // Uncomment successful (sed command)
                'exists'                    // Verification check successful
            );

        $result = $this->manager->configureScreen();
        $this->assertTrue($result);
    }

    /**
     * Test configureScreen() when all settings need to be added
     */
    public function testConfigureScreenAddAllSettings(): void
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->exactly(13))  // 1 backup + (3 settings × 4 checks each)
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                '',                         // Backup command success
                '',                         // First setting doesn't exist (grep for uncommented)
                '',                         // First setting not commented (grep for commented)
                '',                         // Append new line (echo command)
                'exists',                   // Verification check successful
                '',                         // Second setting doesn't exist (grep for uncommented)
                '',                         // Second setting not commented (grep for commented)
                '',                         // Append new line (echo command)
                'exists',                   // Verification check successful
                '',                         // Third setting doesn't exist (grep for uncommented)
                '',                         // Third setting not commented (grep for commented)
                '',                         // Append new line (echo command)
                'exists'                    // Verification check successful
            );

        $result = $this->manager->configureScreen();
        $this->assertTrue($result);
    }

    /**
     * Test configureScreen() when verification fails after update
     */
    public function testConfigureScreenVerificationFails(): void
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->exactly(13))  // 1 backup + (3 settings × 4 checks each)
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                '',                         // Backup command success
                '',                         // First setting doesn't exist (grep for uncommented)
                '',                         // First setting not commented (grep for commented)
                '',                         // Append new line (echo command)
                '',                         // Verification fails (should return 'exists' for success)
                '',                         // Second setting doesn't exist (grep for uncommented)
                '',                         // Second setting not commented (grep for commented)
                '',                         // Append new line (echo command)
                '',                         // Verification fails (should return 'exists' for success)
                '',                         // Third setting doesn't exist (grep for uncommented)
                '',                         // Third setting not commented (grep for commented)
                '',                         // Append new line (echo command)
                ''                          // Verification fails (should return 'exists' for success)
            );

        $result = $this->manager->configureScreen();
        $this->assertFalse($result);
    }

    /**
     * Test successful CyberPanel update with OS update.
     */
    public function testUpdateCyberPanelWithOsUpdateSuccess(): void
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);

        // Store original timeout
        $originalTimeout = 60;
        $this->sshMock->method('getTimeout')->willReturn($originalTimeout);

        // Track timeout calls
        $timeoutCalls = [];
        $this->sshMock->expects($this->exactly(2))
            ->method('setTimeout')
            ->willReturnCallback(function ($timeout) use (&$timeoutCalls) {
                $timeoutCalls[] = $timeout;

                return true;
            });

        // Track exec calls
        $this->sshMock->expects($this->exactly(5))  // 5 executeCommand calls
            ->method('exec')
            ->willReturnCallback(function ($command) {
                if (strpos($command, Manager::NONINTERACTIVE_SHELL) !== false) {
                    // All commands should return success
                    return 'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>';
                }

                return '';
            });

        $result = $this->manager->updateCyberPanel(true, true);

        // Verify timeout was set and restored correctly
        $this->assertEquals([3600, $originalTimeout], $timeoutCalls);
        $this->assertTrue($result);
    }

    /**
     * Test successful CyberPanel update without OS update.
     */
    public function testUpdateCyberPanelWithoutOsUpdateSuccess(): void
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->method('getTimeout')->willReturn(60);

        // Track timeout calls
        $timeoutCalls = [];
        $this->sshMock->expects($this->exactly(2))
            ->method('setTimeout')
            ->willReturnCallback(function ($timeout) use (&$timeoutCalls) {
                $timeoutCalls[] = $timeout;

                return true;
            });

        // Track exec calls
        $this->sshMock->expects($this->exactly(3))  // 3 executeCommand calls
            ->method('exec')
            ->willReturnCallback(function ($command) {
                if (strpos($command, Manager::NONINTERACTIVE_SHELL) !== false) {
                    // All commands should return success
                    return 'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>';
                }

                return '';
            });

        $result = $this->manager->updateCyberPanel(false, true);

        // Verify timeout was set and restored correctly
        $this->assertEquals([3600, 60], $timeoutCalls);
        $this->assertTrue($result);
    }

    /**
     * Test CyberPanel update with OS update failure.
     */
    public function testUpdateCyberPanelOsUpdateFailure(): void
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->method('getTimeout')->willReturn(60);

        // Track timeout calls
        $timeoutCalls = [];
        $this->sshMock->expects($this->exactly(2))
            ->method('setTimeout')
            ->willReturnCallback(function ($timeout) use (&$timeoutCalls) {
                $timeoutCalls[] = $timeout;

                return true;
            });

        // Expect OS update to fail
        $this->sshMock->expects($this->once())
            ->method('exec')
            ->willReturn(false);

        $result = $this->manager->updateCyberPanel(true, true);

        // Verify timeout was set and restored correctly
        $this->assertEquals([3600, 60], $timeoutCalls);

        $this->assertFalse($result);
    }

    // Add new test for update without pip install
    public function testUpdateCyberPanelWithoutPipInstall(): void
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->method('getTimeout')->willReturn(60);

        // Track timeout calls
        $timeoutCalls = [];
        $this->sshMock->expects($this->exactly(2))
            ->method('setTimeout')
            ->willReturnCallback(function ($timeout) use (&$timeoutCalls) {
                $timeoutCalls[] = $timeout;

                return true;
            });

        // Track exec call with the new executeCommand format
        $this->sshMock->expects($this->once())
            ->method('exec')
            ->willReturnCallback(function ($command) {
                // Return success for the update command (exit code 0)
                return 'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>';
            });

        $result = $this->manager->updateCyberPanel(false, false);  // Both OS update and pip install disabled

        // Verify timeout was set and restored correctly
        $this->assertEquals([3600, 60], $timeoutCalls);
        $this->assertTrue($result);
    }

    /**
     * Test CyberPanel update failure.
     */
    public function testUpdateCyberPanelUpdateFailure(): void
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->method('getTimeout')->willReturn(60);

        // Track timeout calls
        $timeoutCalls = [];
        $this->sshMock->expects($this->exactly(2))
            ->method('setTimeout')
            ->willReturnCallback(function ($timeout) use (&$timeoutCalls) {
                $timeoutCalls[] = $timeout;

                return true;
            });

        // Track exec calls
        $this->sshMock->expects($this->exactly(2))  // Updated count to include pip file check
            ->method('exec')
            ->willReturnCallback(function ($command) {
                if (strpos($command, 'test -f') !== false) {
                    return false; // Simulate pip file doesn't exist
                }

                return false; // Simulate command failure
            });

        $result = $this->manager->updateCyberPanel(false);

        // Verify timeout was set and restored correctly
        $this->assertEquals([3600, 60], $timeoutCalls);
        $this->assertFalse($result);
    }

    /**
     * Test CyberPanel update with custom timeout.
     */
    public function testUpdateCyberPanelCustomTimeout(): void
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);

        // Store original timeout
        $originalTimeout = 60;
        $this->sshMock->method('getTimeout')->willReturn($originalTimeout);

        // Track timeout calls
        $timeoutCalls = [];
        $this->sshMock->expects($this->exactly(2))
            ->method('setTimeout')
            ->willReturnCallback(function ($timeout) use (&$timeoutCalls) {
                $timeoutCalls[] = $timeout;

                return true;
            });

        // Track exec call with the new executeCommand format
        $this->sshMock->expects($this->once())
            ->method('exec')
            ->willReturnCallback(function ($command) {
                // Return success for the update command (exit code 0)
                return 'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>';
            });

        // Pass the custom timeout as the third parameter
        $result = $this->manager->updateCyberPanel(false, false, 7200);

        // Verify timeout was set and restored correctly
        $this->assertEquals([7200, $originalTimeout], $timeoutCalls);
        $this->assertTrue($result);
    }

    private function getPrivateMethod($className, $methodName)
    {
        $reflection = new \ReflectionClass($className);
        $method     = $reflection->getMethod($methodName);
        $method->setAccessible(true);

        return $method;
    }

    /**
     * Test successful execution of execSsh with debug disabled
     */
    public function testExecSshSuccess(): void
    {
        // Get private execSsh method
        $execSsh = $this->getPrivateMethod(Manager::class, 'execSsh');

        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->once())
            ->method('exec')
            ->with('test command')
            ->willReturn('command output');

        // Execute the method
        $result = $execSsh->invoke($this->manager, 'test command');

        // Assert
        $this->assertEquals('command output', $result);
    }

    /**
     * Test execSsh with debug mode enabled
     */
    public function testExecSshWithDebugEnabled(): void
    {
        // Get private execSsh method
        $execSsh = $this->getPrivateMethod(Manager::class, 'execSsh');

        // Enable debug mode
        $this->manager->setDebug(true);

        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->once())
            ->method('exec')
            ->with('test command')
            ->willReturn('debug command output');

        // Capture output buffer to verify debug output
        ob_start();
        $result = $execSsh->invoke($this->manager, 'test command', 'test context');
        $output = ob_get_clean();

        // Assert
        $this->assertEquals('debug command output', $result);
        $this->assertStringContainsString('execSsh(test command, test context):', $output);
        $this->assertStringContainsString('debug command output', $output);
    }

    /**
     * Test execSsh with SSH connection failure
     */
    public function testExecSshConnectionFailure(): void
    {
        // Get private execSsh method
        $execSsh = $this->getPrivateMethod(Manager::class, 'execSsh');

        // Configure the SSH mock to fail login
        $this->sshMock->method('login')->willReturn(false);

        // Expect exception
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Login failed.');

        // Execute the method
        $execSsh->invoke($this->manager, 'test command');
    }

    public function testExecuteCommand()
    {
        $executeCommand = $this->getPrivateMethod(Manager::class, 'executeCommand');

        // Set verbose mode to true
        $this->manager->setVerbose(true);

        $this->sshMock->expects($this->once())
            ->method('exec')
            ->with($this->stringContains('test command'))
            ->willReturn('Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>');

        $this->mockLogger->expects($this->once())
            ->method('info')
            ->with(
                'Command output: test command',
                ['output' => 'Command output']
            );

        $result = $executeCommand->invoke($this->manager, 'test command');
        $this->assertTrue($result);
    }

    public function testExecuteCommandFailure()
    {
        $executeCommand = $this->getPrivateMethod(Manager::class, 'executeCommand');

        $this->sshMock->expects($this->once())
            ->method('exec')
            ->willReturn('Error output<<<EXITCODE_DELIMITER>>>1<<<EXITCODE_END>>>');

        $this->mockLogger->expects($this->once())
            ->method('error')
            ->with(
                'Command failed with exit code 1: failing command',
                ['output' => 'Error output']
            );

        $result = $executeCommand->invoke($this->manager, 'failing command');
        $this->assertFalse($result);
    }

    public function testInstallPhpVersionsAndExtensionsSuccess(): void
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->method('getTimeout')->willReturn(60);

        // Track timeout calls
        $timeoutCalls = [];
        $this->sshMock->expects($this->exactly(2))
            ->method('setTimeout')
            ->willReturnCallback(function ($timeout) use (&$timeoutCalls) {
                $timeoutCalls[] = $timeout;

                return true;
            });

        // Track command executions with proper exit code format
        $expectedCommands = [
            'sudo add-apt-repository -y ppa:ondrej/php',
            'sudo apt-get update',
            'sudo apt-get install -y php8.2 php8.3',
            // PHP versions extensions
            [
                'type'       => 'php7.4',
                'extensions' => [
                    'bcmath',
                    'cli',
                    'common',
                    'ctype',
                    'curl',
                    'dev',
                    'dom',
                    'exif',
                    'fileinfo',
                    'gd',
                    'iconv',
                    'intl',
                    'mbstring',
                    'mysql',
                    'opcache',
                    'pdo',
                    'redis',
                    'sqlite3',
                    'tokenizer',
                    'xml',
                    'zip',
                    'json',
                ],
            ],
            [
                'type'       => 'php8.0',
                'extensions' => [
                    'bcmath',
                    'cli',
                    'common',
                    'ctype',
                    'curl',
                    'dev',
                    'dom',
                    'exif',
                    'fileinfo',
                    'gd',
                    'iconv',
                    'intl',
                    'mbstring',
                    'mysql',
                    'opcache',
                    'pdo',
                    'redis',
                    'sqlite3',
                    'tokenizer',
                    'xml',
                    'zip',
                ],
            ],
            [
                'type'       => 'php8.1',
                'extensions' => [
                    'bcmath',
                    'cli',
                    'common',
                    'ctype',
                    'curl',
                    'dev',
                    'dom',
                    'exif',
                    'fileinfo',
                    'gd',
                    'iconv',
                    'intl',
                    'mbstring',
                    'mysql',
                    'opcache',
                    'pdo',
                    'redis',
                    'sqlite3',
                    'tokenizer',
                    'xml',
                    'zip',
                ],
            ],
            [
                'type'       => 'php8.2',
                'extensions' => [
                    'bcmath',
                    'cli',
                    'common',
                    'ctype',
                    'curl',
                    'dev',
                    'dom',
                    'exif',
                    'fileinfo',
                    'gd',
                    'iconv',
                    'intl',
                    'mbstring',
                    'mysql',
                    'opcache',
                    'pdo',
                    'redis',
                    'sqlite3',
                    'tokenizer',
                    'xml',
                    'zip',
                ],
            ],
            [
                'type'       => 'php8.3',
                'extensions' => [
                    'bcmath',
                    'cli',
                    'common',
                    'ctype',
                    'curl',
                    'dev',
                    'dom',
                    'exif',
                    'fileinfo',
                    'gd',
                    'iconv',
                    'intl',
                    'mbstring',
                    'mysql',
                    'opcache',
                    'pdo',
                    'redis',
                    'sqlite3',
                    'tokenizer',
                    'xml',
                    'zip',
                ],
            ],
            'sudo update-alternatives --install /usr/bin/php php /usr/bin/php8.3 1',
            'sudo update-alternatives --set php /usr/bin/php8.3',
        ];

        $commandIndex = 0;
        $this->sshMock->expects($this->exactly(count($expectedCommands)))
            ->method('exec')
            ->willReturnCallback(function ($command) use (&$commandIndex, $expectedCommands) {
                // Remove DEBIAN_FRONTEND prefix and exit code capture suffix
                $cleanCommand = preg_replace('/^DEBIAN_FRONTEND=noninteractive /', '', $command);
                $cleanCommand = preg_replace('/ 2>&1; echo "<<<EXITCODE_DELIMITER>>>\$\?<<<EXITCODE_END>>>"$/', '', $cleanCommand);

                // Handle PHP extension commands specially
                if ($commandIndex >= 3 && $commandIndex <= 7) {
                    if (strpos($cleanCommand, 'sudo apt-get install -y') === 0) {
                        $phpVersion         = $expectedCommands[$commandIndex]['type'];
                        $expectedExtensions = $expectedCommands[$commandIndex]['extensions'];

                        // Extract actual extensions from command
                        preg_match_all("/$phpVersion-(\w+)/", $cleanCommand, $matches);
                        $actualExtensions = $matches[1];

                        // Sort both arrays for comparison
                        sort($expectedExtensions);
                        sort($actualExtensions);

                        if ($expectedExtensions !== $actualExtensions) {
                            return 'Command mismatch<<<EXITCODE_DELIMITER>>>1<<<EXITCODE_END>>>';
                        }
                    }
                } else {
                    // For non-PHP extension commands, do exact match
                    if (strpos($cleanCommand, $expectedCommands[$commandIndex]) === false) {
                        return 'Command mismatch<<<EXITCODE_DELIMITER>>>1<<<EXITCODE_END>>>';
                    }
                }

                $commandIndex++;

                return 'Success<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>';
            });

        $result = $this->manager->installPhpVersionsAndExtensions(true, 1800, '8.3');
        $this->assertTrue($result);
    }

    public function testInstallPhpVersionsAndExtensionsInvalidVersion(): void
    {
        // Configure the SSH mock first
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->method('getTimeout')->willReturn(60);

        // Set the SSH connection
        $this->manager->setSshConnection($this->sshMock);

        // Now test the invalid version
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid PHP version: 8.4');

        $this->manager->installPhpVersionsAndExtensions(true, 1800, '8.4');
    }

    public function testInstallPhpVersionsAndExtensionsCommandFailure(): void
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->method('getTimeout')->willReturn(60);

        // Set the SSH connection
        $this->manager->setSshConnection($this->sshMock);

        // Track timeout calls
        $this->sshMock->expects($this->exactly(2))
            ->method('setTimeout')
            ->willReturnCallback(function ($timeout) {
                return true;
            });

        // Simulate a command failure
        $this->sshMock->expects($this->once())
            ->method('exec')
            ->willReturn('Command failed<<<EXITCODE_DELIMITER>>>1<<<EXITCODE_END>>>');

        // Expect error to be logged
        $this->mockLogger->expects($this->once())
            ->method('error')
            ->with(
                $this->stringContains('Command failed with exit code 1'),
                $this->arrayHasKey('output')
            );

        $result = $this->manager->installPhpVersionsAndExtensions(true, 1800, '8.3');
        $this->assertFalse($result);
    }

    public function testInstallPhpVersionsAndExtensionsTimeoutHandling(): void
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->method('getTimeout')->willReturn(60);

        // Set the SSH connection
        $this->manager->setSshConnection($this->sshMock);

        // Track timeout modifications
        /** @var array<int, string> $timeoutSequence */
        $timeoutSequence = [];
        $this->sshMock->expects($this->exactly(2))
            ->method('setTimeout')
            ->willReturnCallback(function ($timeout) use (&$timeoutSequence) {
                $timeoutSequence[] = $timeout;

                return true;
            });

        // Simulate a command that succeeds but throws an exception later
        $this->sshMock->expects($this->once())
            ->method('exec')
            ->willReturnCallback(function () {
                throw new \Exception('Simulated timeout error');
            });

        // Expect error to be logged
        $this->mockLogger->expects($this->once())
            ->method('error')
            ->with($this->stringContains('Error during PHP installation'));

        $customTimeout = 2400;
        $result        = $this->manager->installPhpVersionsAndExtensions(true, $customTimeout, '8.3');

        $this->assertFalse($result);
        $this->assertEquals($customTimeout, $timeoutSequence[0], 'Custom timeout not set correctly');
        $this->assertEquals(60, $timeoutSequence[1], 'Original timeout not restored');
    }

    /**
     * Test successful installation of LiteSpeed PHP versions and extensions.
     */
    public function testInstallLiteSpeedPhpVersionsAndExtensionsSuccess(): void
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->method('getTimeout')->willReturn(60);

        // Track timeout calls
        $timeoutCalls = [];
        $this->sshMock->expects($this->exactly(2))
            ->method('setTimeout')
            ->willReturnCallback(function ($timeout) use (&$timeoutCalls) {
                $timeoutCalls[] = $timeout;

                return true;
            });

        // Track command executions
        $expectedCommands = [
            'apt-get update',
            // PHP 7.4 packages
            'apt-get install -y lsphp74 lsphp74-apcu lsphp74-common lsphp74-curl lsphp74-dbg ' .
                'lsphp74-dev lsphp74-igbinary lsphp74-imagick lsphp74-imap lsphp74-intl lsphp74-ioncube ' .
                'lsphp74-json lsphp74-ldap lsphp74-memcached lsphp74-modules-source lsphp74-msgpack ' .
                'lsphp74-mysql lsphp74-opcache lsphp74-pear lsphp74-pgsql lsphp74-pspell lsphp74-redis ' .
                'lsphp74-snmp lsphp74-sqlite3 lsphp74-sybase lsphp74-tidy',
            // PHP 8.0 packages
            'apt-get install -y lsphp80 lsphp80-apcu lsphp80-common lsphp80-curl lsphp80-dbg ' .
                'lsphp80-dev lsphp80-igbinary lsphp80-imagick lsphp80-imap lsphp80-intl ' .
                'lsphp80-ldap lsphp80-memcached lsphp80-modules-source lsphp80-msgpack lsphp80-mysql ' .
                'lsphp80-opcache lsphp80-pear lsphp80-pgsql lsphp80-pspell lsphp80-redis lsphp80-snmp ' .
                'lsphp80-sqlite3 lsphp80-sybase lsphp80-tidy',
            // PHP 8.1 packages
            'apt-get install -y lsphp81 lsphp81-apcu lsphp81-common lsphp81-curl lsphp81-dbg ' .
                'lsphp81-dev lsphp81-igbinary lsphp81-imagick lsphp81-imap lsphp81-intl lsphp81-ioncube ' .
                'lsphp81-ldap lsphp81-memcached lsphp81-modules-source lsphp81-msgpack lsphp81-mysql ' .
                'lsphp81-opcache lsphp81-pear lsphp81-pgsql lsphp81-pspell lsphp81-redis lsphp81-snmp ' .
                'lsphp81-sqlite3 lsphp81-sybase lsphp81-tidy',
            // PHP 8.2 packages
            'apt-get install -y lsphp82 lsphp82-apcu lsphp82-common lsphp82-curl lsphp82-dbg ' .
                'lsphp82-dev lsphp82-igbinary lsphp82-imagick lsphp82-imap lsphp82-intl lsphp82-ioncube ' .
                'lsphp82-ldap lsphp82-memcached lsphp82-modules-source lsphp82-msgpack lsphp82-mysql ' .
                'lsphp82-opcache lsphp82-pear lsphp82-pgsql lsphp82-pspell lsphp82-redis lsphp82-snmp ' .
                'lsphp82-sqlite3 lsphp82-sybase lsphp82-tidy',
            // PHP 8.3 packages
            'apt-get install -y lsphp83 lsphp83-apcu lsphp83-common lsphp83-curl lsphp83-dbg ' .
                'lsphp83-dev lsphp83-igbinary lsphp83-imagick lsphp83-imap lsphp83-intl lsphp83-ioncube ' .
                'lsphp83-ldap lsphp83-memcached lsphp83-modules-source lsphp83-msgpack lsphp83-mysql ' .
                'lsphp83-opcache lsphp83-pear lsphp83-pgsql lsphp83-pspell lsphp83-redis lsphp83-snmp ' .
                'lsphp83-sqlite3 lsphp83-sybase lsphp83-tidy',
        ];

        $commandIndex = 0;
        $this->sshMock->expects($this->exactly(count($expectedCommands)))
            ->method('exec')
            ->willReturnCallback(function ($command) use (&$commandIndex, $expectedCommands) {
                // Remove DEBIAN_FRONTEND prefix and exit code capture suffix
                $cleanCommand = preg_replace('/^DEBIAN_FRONTEND=noninteractive /', '', $command);
                $cleanCommand = preg_replace('/ 2>&1; echo "<<<EXITCODE_DELIMITER>>>\$\?<<<EXITCODE_END>>>"$/', '', $cleanCommand);

                // Compare with expected command
                if ($cleanCommand !== $expectedCommands[$commandIndex]) {
                    return 'Command mismatch<<<EXITCODE_DELIMITER>>>1<<<EXITCODE_END>>>';
                }

                $commandIndex++;

                return 'Success<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>';
            });

        // Test installation with default arguments (all versions)
        $result = $this->manager->installLiteSpeedPhpVersionsAndExtensions();

        // Verify timeout was set and restored correctly
        $this->assertEquals([1800, 60], $timeoutCalls);
        $this->assertTrue($result);
    }

    /**
     * Test LiteSpeed PHP installation with invalid version.
     */
    public function testInstallLiteSpeedPhpVersionsAndExtensionsInvalidVersion(): void
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->method('getTimeout')->willReturn(60);

        // Expect an exception for invalid version
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid PHP version: 8.4');

        $this->manager->installLiteSpeedPhpVersionsAndExtensions(true, 1800, ['8.4']);
    }

    /**
     * Test LiteSpeed PHP installation with command failure.
     */
    public function testInstallLiteSpeedPhpVersionsAndExtensionsCommandFailure(): void
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->method('getTimeout')->willReturn(60);

        // Track timeout calls
        $this->sshMock->expects($this->exactly(2))
            ->method('setTimeout')
            ->willReturnCallback(function ($timeout) {
                return true;
            });

        // Simulate a command failure
        $this->sshMock->expects($this->once())
            ->method('exec')
            ->willReturn('Command failed<<<EXITCODE_DELIMITER>>>1<<<EXITCODE_END>>>');

        // Expect error to be logged
        $this->mockLogger->expects($this->once())
            ->method('error')
            ->with(
                $this->stringContains('Command failed with exit code 1'),
                $this->arrayHasKey('output')
            );

        $result = $this->manager->installLiteSpeedPhpVersionsAndExtensions(true, 1800, ['7.4']);
        $this->assertFalse($result);
    }

    public function testConfigurePhpSuccess(): void
    {
        $this->sshMock->method('login')->willReturn(true);
        $this->manager->setSshConnection($this->sshMock);

        // For 5 PHP versions (7.4, 8.0, 8.1, 8.2, 8.3), we expect:
        // - 2 calls per version for symlink creation (10 total)
        // - 5 calls per version for display_errors modification (25 total)
        $this->sshMock->expects($this->exactly(35))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                // PHP 7.4 symlink
                '',  // test -e check
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>', // ln -s

                // PHP 8.0 symlink
                '',  // test -e check
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>', // ln -s

                // PHP 8.1 symlink
                '',  // test -e check
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>', // ln -s

                // PHP 8.2 symlink
                '',  // test -e check
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>', // ln -s

                // PHP 8.3 symlink
                '',  // test -e check
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>', // ln -s

                // PHP 7.4 display_errors
                '',  // grep On check
                'display_errors = Off', // grep Off check
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>', // cp backup
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>', // sed replace
                'display_errors = On',  // grep verify

                // PHP 8.0 display_errors
                '',  // grep On check
                'display_errors = Off', // grep Off check
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>', // cp backup
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>', // sed replace
                'display_errors = On',  // grep verify

                // PHP 8.1 display_errors
                '',  // grep On check
                'display_errors = Off', // grep Off check
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>', // cp backup
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>', // sed replace
                'display_errors = On',  // grep verify

                // PHP 8.2 display_errors
                '',  // grep On check
                'display_errors = Off', // grep Off check
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>', // cp backup
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>', // sed replace
                'display_errors = On',  // grep verify

                // PHP 8.3 display_errors
                '',  // grep On check
                'display_errors = Off', // grep Off check
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>', // cp backup
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>', // sed replace
                'display_errors = On'   // grep verify
            );

        $result = $this->manager->configurePhp(true);
        $this->assertTrue($result);
    }

    /**
     * Test PHP configuration when symlink creation fails.
     */
    public function testConfigurePhpSymlinkFailure(): void
    {
        $this->sshMock->method('login')->willReturn(true);
        $this->manager->setSshConnection($this->sshMock);

        // Simulate symlink creation failure
        $this->sshMock->expects($this->exactly(10))  // 2 calls per version (test -e and ln -s)
            ->method('exec')
            ->willReturnCallback(function ($command) {
                if (str_contains($command, 'test -e')) {
                    return '';  // File doesn't exist
                }

                return 'Command failed<<<EXITCODE_DELIMITER>>>1<<<EXITCODE_END>>>';  // ln -s fails
            });

        // Expect error messages for each version
        $expectedErrors = [
            'Command failed with exit code 1: ln -s',
            'Failed to create symlink for PHP 7.4',
            'Command failed with exit code 1: ln -s',
            'Failed to create symlink for PHP 8.0',
            'Command failed with exit code 1: ln -s',
            'Failed to create symlink for PHP 8.1',
            'Command failed with exit code 1: ln -s',
            'Failed to create symlink for PHP 8.2',
            'Command failed with exit code 1: ln -s',
            'Failed to create symlink for PHP 8.3',
        ];

        $errorIndex = 0;
        $this->mockLogger->expects($this->exactly(10))
            ->method('error')
            ->willReturnCallback(function ($message) use (&$errorIndex, $expectedErrors) {
                $this->assertStringContainsString($expectedErrors[$errorIndex], $message);
                $errorIndex++;
            });

        $result = $this->manager->configurePhp(false);
        $this->assertFalse($result);
    }

    /**
     * Test MySQL configuration when all steps succeed.
     */
    public function testConfigureMySqlSuccess(): void
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);

        // We expect 9 SSH commands to be executed:
        // 1. Backup file
        // 2. Check for [mysqld] section
        // 3. Check for skip-networking
        // 4. Add skip-networking=0
        // 5. Verify skip-networking=0
        // 6. Check for skip-bind-address
        // 7. Add skip-bind-address
        // 8. Verify skip-bind-address
        // 9. MySQL service restart
        // 10. MySQL service status check
        $this->sshMock->expects($this->exactly(10))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                // Backup successful
                '',
                // [mysqld] section exists
                'exists',
                // skip-networking check
                '',
                // Add skip-networking=0 successful
                '',
                // Verify skip-networking=0
                'exists',
                // skip-bind-address check
                '',
                // Add skip-bind-address successful
                '',
                // Verify skip-bind-address
                'exists',
                // MySQL restart successful
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>',
                // MySQL status check successful
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>'
            );

        $result = $this->manager->configureMySql();
        $this->assertTrue($result);
    }

    /**
     * Test MySQL configuration when service restart fails.
     */
    public function testConfigureMySqlServiceRestartFailure(): void
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);

        // All configuration steps succeed but service restart fails
        $this->sshMock->expects($this->exactly(9))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                // Backup successful
                '',
                // [mysqld] section exists
                'exists',
                // skip-networking check
                '',
                // Add skip-networking=0 successful
                '',
                // Verify skip-networking=0
                'exists',
                // skip-bind-address check
                '',
                // Add skip-bind-address successful
                '',
                // Verify skip-bind-address
                'exists',
                // MySQL restart fails
                'Failed to restart MySQL<<<EXITCODE_DELIMITER>>>1<<<EXITCODE_END>>>'
            );

        // Expect two error logs
        $this->mockLogger->expects($this->exactly(2))
            ->method('error')
            ->willReturnCallback(function ($message, $context = []) {
                static $callCount = 0;
                $callCount++;

                if ($callCount === 1) {
                    // First error from executeCommand()
                    $this->assertStringContainsString('Command failed with exit code 1: systemctl restart mysql', $message);
                    $this->assertArrayHasKey('output', $context);
                } else {
                    // Second error from configureMySql()
                    $this->assertEquals('Failed to restart MySQL service', $message);
                }
            });

        $result = $this->manager->configureMySql();
        $this->assertFalse($result);
    }

    /**
     * Test MySQL configuration when verification fails.
     */
    public function testConfigureMySqlVerificationFailure(): void
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);

        // Configuration succeeds but verification fails
        $this->sshMock->expects($this->exactly(5))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                // Backup successful
                '',
                // [mysqld] section exists
                'exists',
                // skip-networking check
                '',
                // Add skip-networking=0 successful
                '',
                // Verify skip-networking=0 fails
                ''  // Empty response means verification failed
            );

        // Expect error to be logged
        $this->mockLogger->expects($this->once())
            ->method('error')
            ->with($this->stringContains('Failed to configure skip-networking'));

        $result = $this->manager->configureMySql();
        $this->assertFalse($result);
    }

    /**
     * Test openFirewall when port is already open
     */
    public function testOpenFirewallPortAlreadyOpen(): void
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->once())
            ->method('exec')
            ->with("firewall-cmd --list-ports | grep '3306/tcp'")
            ->willReturn('3306/tcp');

        $result = $this->manager->openFirewall();
        $this->assertTrue($result);
    }

    /**
     * Test openFirewall with successful port opening
     */
    public function testOpenFirewallSuccess(): void
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->exactly(4))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                '',  // Port not already open
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>', // Add port success
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>', // Reload success
                '3306/tcp'  // Verification succeeds (port found in list)
            );

        $result = $this->manager->openFirewall();
        $this->assertTrue($result);
    }

    /**
     * Test openFirewall with custom port
     */
    public function testOpenFirewallCustomPort(): void
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->exactly(4))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                '',  // Port not already open
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>', // Add port success
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>', // Reload success
                '8080/tcp'  // Verification succeeds (port found in list)
            );

        $result = $this->manager->openFirewall(8080);
        $this->assertTrue($result);
    }

    /**
     * Test openFirewall when add-port command fails
     */
    public function testOpenFirewallAddPortFailure(): void
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->exactly(2))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                '',  // Port not already open
                'Error output<<<EXITCODE_DELIMITER>>>1<<<EXITCODE_END>>>' // Add port failure
            );

        $result = $this->manager->openFirewall();
        $this->assertFalse($result);
    }

    /**
     * Test openFirewall when reload command fails
     */
    public function testOpenFirewallReloadFailure(): void
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->exactly(3))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                '',  // Port not already open
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>', // Add port success
                'Error output<<<EXITCODE_DELIMITER>>>1<<<EXITCODE_END>>>'    // Reload failure
            );

        $result = $this->manager->openFirewall();
        $this->assertFalse($result);
    }

    /**
     * Test openFirewall with verification failure
     */
    public function testOpenFirewallVerificationFailure(): void
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->exactly(4))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                '',  // Port not already open
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>', // Add port success
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>', // Reload success
                ''   // Verification fails (port not found in list)
            );

        $result = $this->manager->openFirewall();
        $this->assertFalse($result);
    }

    /**
     * Test WP-CLI installation when it's already installed.
     */
    public function testInstallWpCliAlreadyInstalled(): void
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->once())
            ->method('exec')
            ->with("wp --info 2>/dev/null | grep -q 'WP-CLI version' && echo 'exists'")
            ->willReturn('exists');

        // Test installation
        $result = $this->manager->installWpCli();
        $this->assertTrue($result);
    }

    /**
     * Test successful WP-CLI installation.
     */
    public function testInstallWpCliSuccess(): void
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->exactly(5))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                '',  // WP-CLI not installed check
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>', // Download
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>', // Make executable
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>', // Move to system dir
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>'  // Verify installation
            );

        // Test installation
        $result = $this->manager->installWpCli();
        $this->assertTrue($result);
    }

    /**
     * Test WP-CLI installation failure during download.
     */
    public function testInstallWpCliDownloadFailure(): void
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->exactly(2))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                '',  // WP-CLI not installed check
                'Download failed<<<EXITCODE_DELIMITER>>>1<<<EXITCODE_END>>>' // Download fails
            );

        // Expect two error logs
        $this->mockLogger->expects($this->exactly(2))
            ->method('error')
            ->willReturnCallback(function ($message, $context = []) {
                static $callCount = 0;
                $callCount++;

                if ($callCount === 1) {
                    // First error from executeCommand()
                    $this->assertStringContainsString('Command failed with exit code 1: curl -o /tmp/wp-cli.phar', $message);
                    $this->assertArrayHasKey('output', $context);
                } else {
                    // Second error from installWpCli()
                    $this->assertEquals('Failed to download WP-CLI', $message);
                }
            });

        // Test installation
        $result = $this->manager->installWpCli();
        $this->assertFalse($result);
    }

    /**
     * Test WP-CLI installation failure when making executable.
     */
    public function testInstallWpCliChmodFailure(): void
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->exactly(3))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                '',  // WP-CLI not installed check
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>', // Download succeeds
                'Chmod failed<<<EXITCODE_DELIMITER>>>1<<<EXITCODE_END>>>'    // Chmod fails
            );

        // Expect two error logs
        $this->mockLogger->expects($this->exactly(2))
            ->method('error')
            ->willReturnCallback(function ($message, $context = []) {
                static $callCount = 0;
                $callCount++;

                if ($callCount === 1) {
                    // First error from executeCommand()
                    $this->assertStringContainsString('Command failed with exit code 1: chmod +x /tmp/wp-cli.phar', $message);
                    $this->assertArrayHasKey('output', $context);
                } else {
                    // Second error from installWpCli()
                    $this->assertEquals('Failed to make WP-CLI executable', $message);
                }
            });

        // Test installation
        $result = $this->manager->installWpCli();
        $this->assertFalse($result);
    }

    /**
     * Test WP-CLI installation failure when moving to system directory.
     */
    public function testInstallWpCliMoveFailure(): void
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->exactly(4))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                '',  // WP-CLI not installed check
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>', // Download succeeds
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>', // Chmod succeeds
                'Move failed<<<EXITCODE_DELIMITER>>>1<<<EXITCODE_END>>>'     // Move fails
            );

        // Expect two error logs
        $this->mockLogger->expects($this->exactly(2))
            ->method('error')
            ->willReturnCallback(function ($message, $context = []) {
                static $callCount = 0;
                $callCount++;

                if ($callCount === 1) {
                    // First error from executeCommand()
                    $this->assertStringContainsString('Command failed with exit code 1: mv /tmp/wp-cli.phar /usr/local/bin/wp', $message);
                    $this->assertArrayHasKey('output', $context);
                } else {
                    // Second error from installWpCli()
                    $this->assertEquals('Failed to move WP-CLI to system directory', $message);
                }
            });

        // Test installation
        $result = $this->manager->installWpCli();
        $this->assertFalse($result);
    }

    /**
     * Test WP-CLI installation failure during verification.
     */
    public function testInstallWpCliVerificationFailure(): void
    {
        // Configure the SSH mock
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->expects($this->exactly(5))
            ->method('exec')
            ->willReturnOnConsecutiveCalls(
                '',  // WP-CLI not installed check
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>', // Download succeeds
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>', // Chmod succeeds
                'Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>', // Move succeeds
                'Verification failed<<<EXITCODE_DELIMITER>>>1<<<EXITCODE_END>>>' // Verification fails
            );

        // Expect two error logs
        $this->mockLogger->expects($this->exactly(2))
            ->method('error')
            ->willReturnCallback(function ($message, $context = []) {
                static $callCount = 0;
                $callCount++;

                if ($callCount === 1) {
                    // First error from executeCommand()
                    $this->assertStringContainsString('Command failed with exit code 1: wp --info', $message);
                    $this->assertArrayHasKey('output', $context);
                } else {
                    // Second error from installWpCli()
                    $this->assertEquals('WP-CLI installation verification failed', $message);
                }
            });

        // Test installation
        $result = $this->manager->installWpCli();
        $this->assertFalse($result);
    }

    /**
     * Test successful droplet configuration with all default parameters.
     */
    public function testConfigureDropletSuccess(): void
    {
        // Configure SSH mock for successful connection and commands
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->method('exec')
            ->willReturn('Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>');

        // Create a partial mock of Manager to mock specific methods
        $managerMock = $this->getMockBuilder(Manager::class)
            ->setConstructorArgs(['test-droplet', $this->mockConfig, $this->mockClient, $this->mockLogger])
            ->onlyMethods([
                'setupAliasesAndFunctions',
                'configureScreen',
                'updateNanoCtrlFSearchBinding',
                'installPhpVersionsAndExtensions',
                'installLiteSpeedPhpVersionsAndExtensions',
                'configurePhp',
                'configureMySql',
                'updateMyCnfPassword',
                'openFirewall',
                'updateCyberPanel',
                'enableCyberPanelApiAccess',
                'updateVhostPy',
                'updateVhostConfsPy',
                'installWpCli',
            ])
            ->getMock();

        // Configure all mocked methods to return true
        $managerMock->method('setupAliasesAndFunctions')->willReturn(true);
        $managerMock->method('configureScreen')->willReturn(true);
        $managerMock->method('updateNanoCtrlFSearchBinding')->willReturn(true);
        $managerMock->method('installPhpVersionsAndExtensions')->willReturn(true);
        $managerMock->method('installLiteSpeedPhpVersionsAndExtensions')->willReturn(true);
        $managerMock->method('configurePhp')->willReturn(true);
        $managerMock->method('configureMySql')->willReturn(true);
        $managerMock->method('updateMyCnfPassword')->willReturn(true);
        $managerMock->method('openFirewall')->willReturn(true);
        $managerMock->method('updateCyberPanel')->willReturn(true);
        $managerMock->method('enableCyberPanelApiAccess')->willReturn(true);
        $managerMock->method('updateVhostPy')->willReturn(true);
        $managerMock->method('updateVhostConfsPy')->willReturn(true);
        $managerMock->method('installWpCli')->willReturn(true);

        // Inject the SSH mock
        $managerMock->setSshConnection($this->sshMock);

        // Call configureDroplet with default parameters
        $result = $managerMock->configureDroplet();

        // Assert that the configuration was successful
        $this->assertTrue($result);
    }

    /**
     * Test droplet configuration when SSH connection fails.
     */
    public function testConfigureDropletSshConnectionFailure(): void
    {
        // Configure SSH mock to fail login
        $this->sshMock->method('login')->willReturn(false);

        // Create manager mock with minimal configuration
        $managerMock = $this->getMockBuilder(Manager::class)
            ->setConstructorArgs(['test-droplet', $this->mockConfig, $this->mockClient, $this->mockLogger])
            ->onlyMethods(['verifyConnectionSsh'])
            ->getMock();

        // Configure verifyConnectionSsh to throw exception
        $managerMock->method('verifyConnectionSsh')
            ->willThrowException(new \Exception('Login failed.'));

        // Expect exception to be thrown
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Login failed.');

        $managerMock->configureDroplet();
    }

    /**
     * Test droplet configuration when PHP installation fails.
     */
    public function testConfigureDropletPhpInstallationFailure(): void
    {
        // Configure SSH mock for successful connection
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->method('exec')
            ->willReturn('Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>');

        // Create a partial mock of Manager
        $managerMock = $this->getMockBuilder(Manager::class)
            ->setConstructorArgs(['test-droplet', $this->mockConfig, $this->mockClient, $this->mockLogger])
            ->onlyMethods([
                'setupAliasesAndFunctions',
                'configureScreen',
                'updateNanoCtrlFSearchBinding',
                'installPhpVersionsAndExtensions',
                'installLiteSpeedPhpVersionsAndExtensions',
                'configurePhp',
                'configureMySql',
                'updateMyCnfPassword',
                'openFirewall',
                'updateCyberPanel',
                'enableCyberPanelApiAccess',
                'updateVhostPy',
                'updateVhostConfsPy',
                'installWpCli',
            ])
            ->getMock();

        // Configure methods to return true except for PHP installation
        $managerMock->method('setupAliasesAndFunctions')->willReturn(true);
        $managerMock->method('configureScreen')->willReturn(true);
        $managerMock->method('updateNanoCtrlFSearchBinding')->willReturn(true);
        $managerMock->method('installPhpVersionsAndExtensions')->willReturn(false); // Simulate failure

        // Expect error to be logged
        $this->mockLogger->expects($this->once())
            ->method('error')
            ->with('Failed to install PHP versions and extensions');

        // Inject the SSH mock
        $managerMock->setSshConnection($this->sshMock);

        // Test configuration
        $result = $managerMock->configureDroplet();
        $this->assertFalse($result);
    }

    /**
     * Test droplet configuration with custom parameters.
     */
    public function testConfigureDropletCustomParameters(): void
    {
        // Configure SSH mock for successful connection
        $this->sshMock->method('login')->willReturn(true);
        $this->sshMock->method('exec')
            ->willReturn('Command output<<<EXITCODE_DELIMITER>>>0<<<EXITCODE_END>>>');

        // Create a partial mock of Manager
        $managerMock = $this->getMockBuilder(Manager::class)
            ->setConstructorArgs(['test-droplet', $this->mockConfig, $this->mockClient, $this->mockLogger])
            ->onlyMethods([
                'setupAliasesAndFunctions',
                'configureScreen',
                'updateNanoCtrlFSearchBinding',
                'installPhpVersionsAndExtensions',
                'installLiteSpeedPhpVersionsAndExtensions',
                'configurePhp',
                'configureMySql',
                'updateMyCnfPassword',
                'openFirewall',
                'updateCyberPanel',
                'enableCyberPanelApiAccess',
                'updateVhostPy',
                'updateVhostConfsPy',
                'installWpCli',
            ])
            ->getMock();

        // Configure all methods to return true
        $managerMock->method('setupAliasesAndFunctions')->willReturn(true);
        $managerMock->method('configureScreen')->willReturn(true);
        $managerMock->method('updateNanoCtrlFSearchBinding')->willReturn(true);
        $managerMock->method('installPhpVersionsAndExtensions')->willReturn(true);
        $managerMock->method('installLiteSpeedPhpVersionsAndExtensions')->willReturn(true);
        $managerMock->method('configurePhp')->willReturn(true);
        $managerMock->method('configureMySql')->willReturn(true);
        $managerMock->method('updateMyCnfPassword')->willReturn(true);
        $managerMock->method('openFirewall')->willReturn(true);
        $managerMock->method('enableCyberPanelApiAccess')->willReturn(true);
        $managerMock->method('updateVhostPy')->willReturn(true);
        $managerMock->method('updateVhostConfsPy')->willReturn(true);
        $managerMock->method('installWpCli')->willReturn(true);

        // Verify that installPhpVersionsAndExtensions is called with custom timeout
        $managerMock->expects($this->once())
            ->method('installPhpVersionsAndExtensions')
            ->with($this->equalTo(true), $this->equalTo(7200))
            ->willReturn(true);

        // Verify that installLiteSpeedPhpVersionsAndExtensions is called with custom timeout
        $managerMock->expects($this->once())
            ->method('installLiteSpeedPhpVersionsAndExtensions')
            ->with($this->equalTo(true), $this->equalTo(7200))
            ->willReturn(true);

        // Verify that configurePhp is called with display_errors disabled
        $managerMock->expects($this->once())
            ->method('configurePhp')
            ->with($this->equalTo(false))
            ->willReturn(true);

        // Verify that openFirewall is called with custom port
        $managerMock->expects($this->once())
            ->method('openFirewall')
            ->with($this->equalTo(8080))
            ->willReturn(true);

        // Verify that updateCyberPanel is never called since updateCyberPanel is false
        $managerMock->expects($this->never())
            ->method('updateCyberPanel');

        // Inject the SSH mock
        $managerMock->setSshConnection($this->sshMock);

        // Test configuration with custom parameters
        $result = $managerMock->configureDroplet(
            updateApt: true,
            timeout: 7200,
            phpDisplayErrors: false,
            mysqlPort: 8080,
            updateCyberPanel: false,
            updateOs: false,
            pipInstall: false
        );

        $this->assertTrue($result);
    }
}
