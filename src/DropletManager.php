<?php

namespace FOfX\DropletManager;

use phpseclib3\Net\SSH2;
use DigitalOceanV2\Client as DigitalOceanClient;

/**
 * DropletManager class
 *
 * This class is responsible for managing DigitalOcean droplets, including creating
 * and deleting droplets.
 */
class DropletManager
{
    private $config;
    private $cyberApi;
    private $dropletName;
    private $sshConnection;
    private $digitalOceanClient;
    private $digitalOceanClientIsAuthenticated = false;
    private $cyberLinkConnection;

    /**
     * Constructor: Retrieve the configuration for DigitalOcean droplet management.
     *
     * @param string|array|null   $config             The path to the configuration file. Or a config array, for testing.
     * @param ?string             $dropletName        The name of the droplet to manage.
     * @param ?DigitalOceanClient $digitalOceanClient The DigitalOcean client to use for API calls.
     */
    public function __construct(string|array|null $config = 'config' . DIRECTORY_SEPARATOR . 'droplet-manager.config.php', ?string $dropletName = null, ?DigitalOceanClient $digitalOceanClient = null)
    {
        if (is_array($config)) {
            // Allow passing the configuration as an array (e.g., for testing purposes)
            $this->config = $config;
        } else {
            // Load the configuration from a file
            $configFilePath = resolve_config_file_path($config);
            if (!$configFilePath) {
                throw new \Exception('Configuration file not found.');
            }
            $this->config = load_config($configFilePath);
        }

        $this->dropletName = $dropletName;
        // Optionally set the DigitalOcean client, allowing it to be injected for testing
        $this->digitalOceanClient = $digitalOceanClient ?? new DigitalOceanClient();
    }

    /**
     * Set the name of the droplet to manage.
     *
     * @param string $dropletName The name of the droplet to manage.
     */
    public function setDropletName(string $dropletName)
    {
        $this->dropletName = $dropletName;
    }

    /**
     * Get the name of the droplet being managed.
     *
     * @return string The name of the droplet being managed.
     */
    public function getDropletName(): string
    {
        return $this->dropletName;
    }

    /**
     * Verifies an SSH connection to the droplet.
     *
     * This method establishes an SSH connection to the server using the droplet's
     * configuration details (server IP and root password). It throws an exception
     * if the login fails or if the droplet configuration is not found.
     *
     * @throws \Exception If the droplet configuration is missing or if SSH login fails.
     *
     * @return bool Returns true if the SSH connection is successfully established.
     */
    public function verifyConnectionSsh(): bool
    {
        if (!isset($this->config[$this->dropletName])) {
            throw new \Exception("Configuration for droplet {$this->dropletName} not found.");
        }

        $serverIp     = $this->config[$this->dropletName]['server_ip'];
        $rootPassword = $this->config[$this->dropletName]['root_password'];

        // Use the existing SSH2 instance, or create one if it's not provided
        $this->sshConnection = $this->sshConnection ?? new SSH2($serverIp);

        if (!$this->sshConnection->login('root', $rootPassword)) {
            throw new \Exception('Login failed.');
        }

        return true;
    }

    /**
     * Verifies a connection to the droplet using the CyberPanel API.
     *
     * This method establishes a connection to the CyberPanel API using the server's
     * configuration details (server IP, port, admin username, and password). It throws
     * an exception if the droplet configuration is not found, or if the API connection fails.
     *
     * @throws \Exception If the droplet configuration is missing or if the API connection fails.
     *
     * @return bool Returns true if the API connection is successfully verified, false otherwise.
     */
    public function verifyConnectionCyberApi(): bool
    {
        try {
            // Ensure droplet config exists
            if (!isset($this->config[$this->dropletName])) {
                throw new \Exception("Configuration for droplet {$this->dropletName} not found.");
            }

            $serverIp  = $this->config[$this->dropletName]['server_ip'];
            $port      = $this->config[$this->dropletName]['port'];
            $adminUser = $this->config[$this->dropletName]['admin'];
            $adminPass = $this->config[$this->dropletName]['password'];

            // Use the existing CyberApi instance, or create a new one if it's not provided
            $this->cyberApi = $this->cyberApi ?? new CyberApi($serverIp, $port);

            // Call verify_connection() with admin credentials
            $response = $this->cyberApi->verify_connection([
                'adminUser' => $adminUser,
                'adminPass' => $adminPass,
            ]);

            // Check if the response is false or invalid
            if (!$response || !$response['verifyConn']) {
                echo 'Error at login.' . PHP_EOL;

                return false;
            }
        } catch (\Exception $e) {
            echo $e->getMessage() . PHP_EOL;

            return false;
        }

        return true;
    }

    /**
     * Authenticates the DigitalOcean client, if not already authenticated.
     *
     * This method authenticates the DigitalOcean client using the provided token.
     * It sets the client as authenticated and allows for subsequent API calls.
     *
     * @return void
     */
    public function authenticateDigitalOcean(): void
    {
        if (!$this->digitalOceanClientIsAuthenticated) {
            $this->digitalOceanClient->authenticate($this->config['digitalocean']['token']);
            $this->digitalOceanClientIsAuthenticated = true;
        }
    }

    /**
     * Creates a new droplet in DigitalOcean.
     *
     * This method authenticates the user with the DigitalOcean API, creates a new droplet
     * with the specified name, region, and size, and monitors the droplet's status until
     * it becomes active. The server's IP address is returned once the droplet is ready.
     * If the creation process times out, a message is displayed.
     *
     * @param string $name          The name of the droplet to create.
     * @param string $region        The region where the droplet will be created.
     * @param string $size          The size of the droplet.
     * @param float  $sleepDuration The duration to sleep between checks in seconds.
     *
     * @throws \Exception If the DigitalOcean configuration is missing or any error occurs.
     *
     * @return ?string Returns the droplet's IP address if created successfully, null otherwise.
     */
    public function createDroplet(string $name, string $region, string $size, float $sleepDuration = 5.0): ?string
    {
        // Track the start time with microsecond precision
        $startTime = microtime(true);

        // Authenticate the client if not already authenticated
        $this->authenticateDigitalOcean();

        // Create a new droplet
        $dropletApi     = $this->digitalOceanClient->droplet();
        $createdDroplet = $dropletApi->create($name, $region, $size, $this->config['digitalocean']['image_id']);

        echo "Droplet with ID: {$createdDroplet->id} created" . PHP_EOL;
        echo 'Launching the server, please wait...';

        // Poll the droplet's status until it's active
        for ($i = 0; $i < 35; $i++) {
            $dropletInfo = $dropletApi->getById($createdDroplet->id);
            if ($dropletInfo->status === 'active') {
                $duration = round(microtime(true) - $startTime, 2);
                echo PHP_EOL . 'Server is ON!' . PHP_EOL;
                echo "Droplet Name: {$dropletInfo->name}" . PHP_EOL;
                echo 'The server IP is: ' . $dropletInfo->networks[0]->ipAddress . PHP_EOL;
                echo "Droplet creation took {$duration} seconds." . PHP_EOL;

                return $dropletInfo->networks[0]->ipAddress;
            }
            echo '...';
            float_sleep($sleepDuration);
        }

        // If droplet creation timed out
        $duration = round(microtime(true) - $startTime, 2);
        echo PHP_EOL . 'Server creation timed out.' . PHP_EOL;
        echo "Droplet creation attempted for {$duration} seconds." . PHP_EOL;

        return null;
    }

    /**
     * Establishes a connection to the droplet using CyberLink.
     *
     * This method either uses the injected CyberLink instance, the existing CyberLink connection,
     * or creates a new one using the server IP and root password from the droplet's configuration.
     *
     * @param ?CyberLink $cyberLinkClient Optional injected CyberLink instance for testing.
     *
     * @return CyberLink Returns the CyberLink connection instance.
     */
    public function connectCyberLink(?CyberLink $cyberLinkClient = null): CyberLink
    {
        // If a CyberLink client is passed, prioritize that over the existing connection
        // Else if an existing connection is set, use that
        // Else create a new connection
        return $cyberLinkClient ?? $this->cyberLinkConnection ?? $this->cyberLinkConnection = new CyberLink(
            $this->config[$this->dropletName]['server_ip'],
            'root',
            $this->config[$this->dropletName]['root_password']
        );
    }

    /**
     * Checks if a domain is configured on DigitalOcean.
     *
     * This method authenticates the DigitalOcean client and attempts to retrieve
     * the domain information by name. If the domain is not found, it returns false.
     *
     * @param string $domainName The name of the domain to check.
     *
     * @return bool Returns true if the domain is configured, false otherwise.
     */
    public function isDomainConfigured(string $domainName): bool
    {
        // Authenticate the client if not already authenticated
        $this->authenticateDigitalOcean();

        try {
            $this->digitalOceanClient->domain()->getByName($domainName);
            return true;
        } catch (\DigitalOceanV2\Exception\ResourceNotFoundException $e) {
            return false;
        }
    }

    /**
     * Get the websites hosted on the droplet.
     * 
     * This method connects to the droplet using CyberLink and retrieves the list of websites hosted on the droplet.
     *
     * @return array An array of website information.
     */
    public function getWebsites(): array
    {
        return $this->connectCyberLink()->listWebsites();
    }

    public function configureDns(string $domainName, string $serverIp)
    {
        // Authenticate the client if not already authenticated
        $this->authenticateDigitalOcean();

        $domainClient = $this->digitalOceanClient->domain();
        $domainRecordClient = $this->digitalOceanClient->domainRecord();

        $configured = $this->isDomainConfigured($domainName);
    }
}
