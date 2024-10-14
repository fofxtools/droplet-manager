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
    }

    /**
     * Test setting and getting the droplet name.
     */
    public function testSetAndGetDropletName(): void
    {
        $this->manager->setDropletName('new-droplet');
        $this->assertSame('new-droplet', $this->manager->getDropletName());
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
        $createdDroplet = (object) ['id' => 12345];
        $dropletInfo    = (object) [
            'status'   => 'active',
            'name'     => 'test-droplet',
            'networks' => [(object) ['ipAddress' => '192.168.1.1']],
        ];

        $this->mockDropletApi->method('create')->willReturn($createdDroplet);
        $this->mockDropletApi->method('getById')->willReturn($dropletInfo);

        // Call createDroplet and expect the IP address to be returned
        $ipAddress = $this->manager->createDroplet('test-droplet', 'nyc3', 's-1vcpu-1gb');

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
        $ipAddress = $this->manager->createDroplet('test-droplet', 'nyc3', 's-1vcpu-1gb', 0.001);

        // Expect null because of timeout
        $this->assertNull($ipAddress);
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
        $this->assertTrue($this->manager->isDomainConfigured('example.com'));
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
        $this->assertFalse($this->manager->isDomainConfigured('nonexistent.com'));
    }

    /**
     * Test getWebsites returns an array of websites.
     */
    public function testGetWebsitesReturnsArray()
    {
        $this->setUpWithCyberLink();

        // Mock the listWebsites() method to return a sample array of websites
        $this->cyberLinkMock->method('listWebsites')->willReturn([
            ['domain' => 'example.com', 'status' => 'active'],
            ['domain' => 'test.com', 'status' => 'inactive'],
        ]);

        // Call getWebsites and check that the result is as expected
        $result = $this->managerWithCyberLink->getWebsites();

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
                $this->stringContains(escapeshellarg(\FOfX\DropletManager\sanitize_domain_for_database($domainName, $username))),
                $this->stringContains(escapeshellarg($username)),
                $this->stringContains(escapeshellarg($password))
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

        // Mock the exec method to simulate successful execution of the sed command
        $this->sshMock->method('exec')->willReturn('');  // Simulate success by returning an empty string

        // Call the method and assert that it returns true on success
        $result = $this->manager->enableSymlinksForDomain($domainName);
        $this->assertTrue($result);
    }

    public function testEnableSymlinksForDomainCommandFailure(): void
    {
        $domainName = 'example.com';

        // Mock the SSH login to return true for successful connection
        $this->sshMock->method('login')->willReturn(true);

        // Mock the exec method to return false, simulating a command failure
        $this->sshMock->method('exec')->willReturn(false);

        // Call the method and assert that it returns false on command failure
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
        $response = (object)[
            'ApiResponse' => (object)['_Status' => 'OK'],
        ];

        $this->domainsDnsMock->method('setCustom')->willReturn($response);

        // Run the method with the mocked DomainsDns
        $result = $this->manager->updateNameserversNamecheap('example.com', false, $this->mockNamecheapApi, $this->domainsDnsMock);

        // Verify result is true for success
        $this->assertTrue($result);
    }

    public function testUpdateNameserversNamecheapApiError()
    {
        // Set up the expectation for logging
        $this->mockLogger->expects($this->once())
            ->method('error')
            ->with($this->stringContains('Error updating nameservers'));

        // Mock an error response from the API
        $response = (object)[
            'ApiResponse' => (object)[
                '_Status' => 'ERROR',
                'Errors'  => (object)[
                    'Error' => (object)['__text' => 'Parameter Nameservers is Missing'],
                ],
            ],
        ];

        $this->domainsDnsMock->method('setCustom')->willReturn($response);

        // Run the method with the mocked DomainsDns
        $result = $this->manager->updateNameserversNamecheap('example.com', false, $this->mockNamecheapApi, $this->domainsDnsMock);

        // Verify result is false for error
        $this->assertFalse($result);
    }

    public function testUpdateNameserversNamecheapUsesSandbox()
    {
        // Mock a successful API response
        $response = (object)[
            'ApiResponse' => (object)['_Status' => 'OK'],
        ];

        $this->domainsDnsMock->method('setCustom')->willReturn($response);

        // Inject the mock NamecheapApi with sandbox enabled
        $sandboxApi = $this->createMock(NamecheapApi::class);
        $sandboxApi->expects($this->once())->method('enableSandbox');

        // Run the method with the sandbox API and mocked DomainsDns
        $result = $this->manager->updateNameserversNamecheap('example.com', true, $sandboxApi, $this->domainsDnsMock);

        // Assert result is true for success
        $this->assertTrue($result);
    }
}