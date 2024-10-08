<?php

namespace FOfX\DropletManager;

use phpseclib3\Net\SSH2;
use DigitalOceanV2\Client as DigitalOceanClient;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Monolog\Level;

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
    private Logger $logger;

    /**
     * Constructor: Retrieve the configuration for DigitalOcean droplet management.
     *
     * @param ?string             $dropletName        The name of the droplet to manage.
     * @param string|array|null   $config             The path to the configuration file. Or a config array, for testing.
     * @param ?DigitalOceanClient $digitalOceanClient The DigitalOcean client to use for API calls.
     * @param ?Logger             $logger             The logger to use for logging.
     */
    public function __construct(
        ?string $dropletName = null,
        string|array|null $config = 'config' . DIRECTORY_SEPARATOR . 'droplet-manager.config.php',
        ?DigitalOceanClient $digitalOceanClient = null,
        ?Logger $logger = null
    ) {
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

        // Set up the logger, with settings from config if logger not provided
        if ($logger === null) {
            $logPath  = $this->config['logging']['path'] ?? 'php://stdout';
            $logLevel = $this->config['logging']['level'] ?? Level::Info;

            $this->logger = new Logger('default');
            $this->logger->pushHandler(new StreamHandler($logPath, $logLevel));
        } else {
            $this->logger = $logger;
        }
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
            $port      = $this->config[$this->dropletName]['cyberpanel_port'];
            $adminUser = $this->config[$this->dropletName]['cyberpanel_admin'];
            $adminPass = $this->config[$this->dropletName]['cyberpanel_password'];

            // Use the existing CyberApi instance, or create a new one if it's not provided
            $this->cyberApi = $this->cyberApi ?? new CyberApi($serverIp, $port);

            // Call verify_connection() with admin credentials
            $response = $this->cyberApi->verify_connection([
                'adminUser' => $adminUser,
                'adminPass' => $adminPass,
            ]);

            // Check if the response is false or invalid
            if (!$response || !$response['verifyConn']) {
                $this->logger->info('Error at login.');

                return false;
            }
        } catch (\Exception $e) {
            $this->logger->error($e->getMessage());

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

        $this->logger->info("Droplet with ID: {$createdDroplet->id} created");
        $this->logger->info('Launching the server, please wait...');

        // Poll the droplet's status until it's active
        for ($i = 0; $i < 35; $i++) {
            $dropletInfo = $dropletApi->getById($createdDroplet->id);
            if ($dropletInfo->status === 'active') {
                $duration = round(microtime(true) - $startTime, 2);
                $this->logger->info('Server is ON!');
                $this->logger->info("Droplet Name: {$dropletInfo->name}");
                $this->logger->info('The server IP is: ' . $dropletInfo->networks[0]->ipAddress);
                $this->logger->info("Droplet creation took {$duration} seconds.");

                return $dropletInfo->networks[0]->ipAddress;
            }
            $this->logger->info('...');
            float_sleep($sleepDuration);
        }

        // If droplet creation timed out
        $duration = round(microtime(true) - $startTime, 2);
        $this->logger->info('Server creation timed out.');
        $this->logger->info("Droplet creation attempted for {$duration} seconds.");

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

    /**
     * Configure the DNS for a domain.
     *
     * This method authenticates the DigitalOcean client and attempts to configure
     * the DNS for the specified domain. It checks if the domain is already configured
     * and updates the DNS records accordingly.
     *
     * @param string $domainName The name of the domain to configure.
     * @param string $serverIp   The IP address of the server.
     *
     * @return void
     */
    public function configureDns(string $domainName, string $serverIp): void
    {
        // Authenticate the client if not already authenticated
        $this->authenticateDigitalOcean();

        $domainClient       = $this->digitalOceanClient->domain();
        $domainRecordClient = $this->digitalOceanClient->domainRecord();

        $configured = $this->isDomainConfigured($domainName);

        // If the domain is already configured, update it
        if ($configured) {
            $this->logger->info("Domain $domainName already registered on the DigitalOcean DNS. Updating...");

            $domainRecords     = $domainRecordClient->getAll($domainName);
            $totalARecords     = 0;
            $totalCnameRecords = 0;

            foreach ($domainRecords as $record) {
                if ($record->type === 'A' && $record->name === '@') {
                    $totalARecords++;
                    $this->logger->info('Old value: A Record: ' . $record->data);

                    if ($record->data !== $serverIp) {
                        $this->logger->info('Updating IP...');
                        $domainRecordClient->update($domainName, $record->id, '@', $serverIp);
                        $this->logger->info('A Record IP updated to: ' . $serverIp);
                    } else {
                        $this->logger->info('The IP was already set. No need to update.');
                    }
                } elseif ($record->type === 'CNAME' && $record->name === 'www') {
                    $totalCnameRecords++;
                    $this->logger->info('Old value: CNAME Record: ' . $record->data);

                    if ($record->data !== '@') {
                        $domainRecordClient->update($domainName, $record->id, 'www', '@');
                        $this->logger->info('CNAME record for "www" updated to point to: @');
                    } else {
                        $this->logger->info('The CNAME record was already set. No need to update.');
                    }
                }
            }

            // If no A record is found, create one
            if (!$totalARecords) {
                $domainRecordClient->create($domainName, 'A', '@', $serverIp);
                $this->logger->info('A Record was not found. Created!');
            }

            // If no CNAME record is found, create one
            if (!$totalCnameRecords) {
                $domainRecordClient->create($domainName, 'CNAME', 'www', '@');
                $this->logger->info('CNAME Record was not found. Created!');
            }
        } else {
            // If the domain was not configured, create it
            $domainClient->create($domainName);
            $domainRecordClient->create($domainName, 'A', '@', $serverIp);
            $domainRecordClient->create($domainName, 'CNAME', 'www', '@');
            $this->logger->info("Domain $domainName was not found. Created!");
        }
    }

    /**
     * Create a new website on the droplet using the CyberPanel API.
     *
     * This method prepares the necessary parameters for creating a new website on the droplet
     * using the CyberPanel API. It then calls the CyberPanel API to create the website and logs
     * the result of the operation.
     *
     * @param array $data The data required to create the website.
     *
     * @return array|bool Returns the API response if the website was created successfully, false otherwise.
     */
    public function createWebsiteCyberApi(array $data): array|bool
    {
        // Prepare parameters for API call
        $params = [
            'adminUser'     => $this->config[$this->dropletName]['cyberpanel_admin'],
            'adminPass'     => $this->config[$this->dropletName]['cyberpanel_password'],
            'domainName'    => $data['domainName'],
            'ownerEmail'    => $data['email'],
            'websiteOwner'  => $data['username'],
            'ownerPassword' => $data['password'],
            'packageName'   => 'Default',
        ];

        // Connect to the CyberPanel API if not already connected
        $this->verifyConnectionCyberApi();

        // Call CyberPanel API to create the website
        $response = $this->cyberApi->create_new_account($params);

        if (!$response['createWebSiteStatus']) {
            $this->logger->info('Website creation failed: ' . $response['error_message']);

            return false;
        }

        $this->logger->info('Website created successfully for domain: ' . $data['domainName']);

        return $response;
    }

    /**
     * Delete an existing website on the droplet using the CyberPanel API.
     *
     * Note that this does not delete the user from the system, it just deletes the website.
     *
     * This method prepares the necessary parameters for deleting a website on the droplet
     * using the CyberPanel API. It then calls the CyberPanel API to delete the website and logs
     * the result of the operation.
     *
     * @param array $data The data required to delete the website.
     *
     * @return array|bool Returns the API response if the website was deleted successfully, false otherwise.
     */
    public function deleteWebsiteCyberApi(array $data): array|bool
    {
        // Prepare parameters for API call
        $params = [
            'adminUser'  => $this->config[$this->dropletName]['cyberpanel_admin'],
            'adminPass'  => $this->config[$this->dropletName]['cyberpanel_password'],
            'domainName' => $data['domainName'],
        ];

        // Connect to the CyberPanel API if not already connected
        $this->verifyConnectionCyberApi();

        // Call CyberPanel API to delete the website
        $response = $this->cyberApi->terminate_account($params);

        // Check for success and log accordingly
        if (isset($response['status']) && $response['status'] === 1) {
            $this->logger->info('Website deleted successfully for domain: ' . $data['domainName']);

            return $response;
        } else {
            $this->logger->info('Website deletion failed: ' . ($response['error_message'] ?? 'Unknown error'));

            return false;
        }
    }
}
