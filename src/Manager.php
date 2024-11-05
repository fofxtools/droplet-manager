<?php

namespace FOfX\DropletManager;

use phpseclib3\Net\SSH2;
use DigitalOceanV2\Client as DigitalOceanClient;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Monolog\Level;
use Namecheap\Api as NamecheapApi;
use Namecheap\Domain\DomainsDns;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use FOfX\Helper;

/**
 * Manager class
 *
 * This class is responsible for managing DigitalOcean droplets, including creating
 * and deleting droplets.
 */
class Manager
{
    // Used to prevent interactive prompts in non-interactive shell
    public const NONINTERACTIVE_SHELL = 'DEBIAN_FRONTEND=noninteractive';

    private array $config;
    private ?string $dropletName                    = null;
    private bool $verbose                           = false;
    private bool $debug                             = false;
    private bool $sshAuthenticated                  = false;
    private bool $digitalOceanClientIsAuthenticated = false;
    private ?CyberApi $cyberApi                     = null;
    private ?SSH2 $sshConnection                    = null;
    private ?DigitalOceanClient $digitalOceanClient = null;
    private ?CyberLink $cyberLinkConnection         = null;
    private ?NamecheapApi $namecheapApi             = null;
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
            $configFilePath = Helper\resolve_config_file_path($config);
            if (!$configFilePath) {
                throw new \Exception('Configuration file not found.');
            }
            $this->config = Helper\load_config($configFilePath);
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
     * Set whether to display verbose command output.
     *
     * @param bool $verbose Whether to show detailed command output.
     *
     * @return void
     */
    public function setVerbose(bool $verbose): void
    {
        $this->verbose = $verbose;
    }

    /**
     * Get whether verbose command output is enabled.
     *
     * @return bool
     */
    public function isVerbose(): bool
    {
        return $this->verbose;
    }

    public function setDebug(bool $debug): void
    {
        $this->debug = $debug;
    }

    public function isDebug(): bool
    {
        return $this->debug;
    }

    /**
     * Set the name of the droplet to manage.
     *
     * @param string $dropletName The name of the droplet to manage.
     */
    public function setDropletName(string $dropletName): void
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
     * Set the SSH connection (mainly for testing purposes).
     *
     * @param SSH2 $sshConnection
     *
     * @return void
     */
    public function setSshConnection(SSH2 $sshConnection): void
    {
        $this->sshConnection = $sshConnection;
    }

    /**
     * Verifies or establishes an SSH connection to the droplet.
     *
     * This method checks if an SSH connection is already authenticated. If not, it
     * establishes a new SSH connection to the server using the droplet's
     * configuration details (server IP and root password). It throws an exception
     * if the login fails or if the droplet configuration is not found.
     *
     * @throws \Exception If the droplet configuration is missing or if SSH login fails.
     *
     * @return bool Returns true if the SSH connection is already authenticated or successfully established.
     */
    public function verifyConnectionSsh(): bool
    {
        if ($this->sshAuthenticated) {
            return true;
        }

        if (!isset($this->config[$this->dropletName])) {
            throw new \Exception("Configuration for droplet {$this->dropletName} not found.");
        }

        $serverIp     = $this->config[$this->dropletName]['server_ip'];
        $rootPassword = $this->config[$this->dropletName]['root_password'];

        if (!$this->sshConnection) {
            $this->sshConnection = new SSH2($serverIp);
        }

        if (!$this->sshConnection->login('root', $rootPassword)) {
            throw new \Exception('Login failed.');
        }

        $this->sshAuthenticated = true;

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
     * it becomes active. The droplet's information is returned once it's ready.
     * If the creation process times out, null is returned.
     *
     * @param string $name          The name of the droplet to create.
     * @param string $region        The region where the droplet will be created.
     * @param string $size          The size of the droplet.
     * @param float  $sleepDuration The duration to sleep between checks in seconds.
     *
     * @throws \Exception If the DigitalOcean configuration is missing or any error occurs.
     *
     * @return ?array Returns the droplet's information if created successfully, null otherwise.
     */
    public function createDroplet(string $name, string $region, string $size, float $sleepDuration = 5.0): ?array
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
        for ($i = 0; $i < 30; $i++) {
            $dropletInfo = $dropletApi->getById($createdDroplet->id);
            if ($dropletInfo->status === 'active') {
                $duration = round(microtime(true) - $startTime, 2);
                $this->logger->info('Server is ON!');
                $this->logger->info("Droplet Name: {$dropletInfo->name}");
                $this->logger->info('The server IP is: ' . $dropletInfo->networks[0]->ipAddress);
                $this->logger->info("Droplet creation took {$duration} seconds.");

                // Return the droplet info as an array
                $dropletInfoArray = [
                    'id'        => $dropletInfo->id,
                    'name'      => $dropletInfo->name,
                    'status'    => $dropletInfo->status,
                    'memory'    => $dropletInfo->memory,
                    'vcpus'     => $dropletInfo->vcpus,
                    'disk'      => $dropletInfo->disk,
                    'region'    => $dropletInfo->region->slug,
                    'image'     => $dropletInfo->image->slug,
                    'kernel'    => $dropletInfo->kernel->id,
                    'size'      => $dropletInfo->size->slug,
                    'createdAt' => $dropletInfo->createdAt,
                    'networks'  => array_map(fn ($network) => [
                        'ipAddress' => $network->ipAddress,
                        'type'      => $network->type,
                        'netmask'   => $network->netmask,
                        'gateway'   => $network->gateway,
                    ], $dropletInfo->networks),
                    'tags'     => $dropletInfo->tags,
                    'features' => $dropletInfo->features,
                    'vpcUuid'  => $dropletInfo->vpcUuid,
                ];

                // The public IP should be: $dropletInfoArray['networks'][0]['ipAddress'];
                return $dropletInfoArray;
            }
            $this->logger->info('...');
            Helper\float_sleep($sleepDuration);
        }

        // If droplet creation timed out
        $duration = round(microtime(true) - $startTime, 2);
        $this->logger->error('Server creation timed out.');
        $this->logger->error("Droplet creation attempted for {$duration} seconds.");

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
     * @param bool $namesOnly If true, the method will return an array of website names only.
     *
     * @return array An array of website information.
     */
    public function getWebsites(bool $namesOnly = true): array
    {
        return $this->connectCyberLink()->listWebsites($namesOnly);
    }

    /**
     * Get the users on the droplet.
     *
     * This method connects to the droplet using CyberLink and retrieves the list of users on the droplet.
     *
     * @param bool $namesOnly If true, the method will return an array of user names only.
     *
     * @return array An array of user information.
     */
    public function getUsers(bool $namesOnly = true): array
    {
        return $this->connectCyberLink()->listUsers($namesOnly);
    }

    /**
     * Get the databases on the droplet for a given domain.
     *
     * This method connects to the droplet using CyberLink and retrieves the list of databases on the droplet
     * for a given domain.
     *
     * @param string $domain    The domain name to retrieve databases for.
     * @param bool   $namesOnly If true, the method will return an array of database names only.
     *
     * @return array An array of database information.
     */
    public function getDatabases(string $domain, bool $namesOnly = true): array
    {
        return $this->connectCyberLink()->listDatabases($domain, $namesOnly);
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
            $this->logger->error('Website creation failed: ' . $response['error_message']);

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
            $this->logger->error('Website deletion failed: ' . ($response['error_message'] ?? 'Unknown error'));

            return false;
        }
    }

    /**
     * Get the Linux user associated with a given domain on the droplet.
     *
     * This method establishes an SSH connection to the droplet and retrieves
     * the owner (Linux user) of the specified domain's directory.
     *
     * @param string $domain The domain name to look up the Linux user for.
     *
     * @throws \Exception If SSH connection or command execution fails.
     *
     * @return string|bool The Linux username if found, false otherwise.
     */
    public function getLinuxUserForDomain(string $domain): string|bool
    {
        // Ensure SSH connection is established
        $this->verifyConnectionSsh();

        // Execute the stat command to get the user owner of the directory
        $command = sprintf('stat -c "%%U" /home/%s', Helper\escapeshellarg_linux($domain));
        $output  = Helper\trim_if_string($this->execSsh($command));

        // Check for error in the command output or empty response
        if (str_contains($output, 'stat: ') || empty($output)) {
            $this->logger->error("Failed to retrieve user for domain {$domain}: {$output}");

            return false;
        }

        // Log and return the retrieved username
        $this->logger->info("Retrieved Linux user for domain {$domain}: {$output}");

        return $output;
    }

    /**
     * Create or update the .htaccess file to enforce HTTPS redirection for a given domain.
     *
     * This method uses an SSH connection to the droplet and creates or modifies
     * the .htaccess file in the domain's public_html directory to redirect HTTP traffic to HTTPS.
     *
     * @param string $domainName        The domain name for which HTTPS redirection should be configured.
     * @param bool   $overwriteHtaccess If true, the .htaccess file will be overwritten if it already exists.
     *
     * @return bool True if the file was created and configured successfully, false on failure.
     */
    public function createHtaccessForHttpsRedirect(string $domainName, bool $overwriteHtaccess = false): bool
    {
        // Ensure SSH connection is established
        $this->verifyConnectionSsh();

        $htaccessPath = "/home/{$domainName}/public_html/.htaccess";

        // Check if .htaccess already exists
        $checkCommand = "test -f {$htaccessPath} && echo 'exists' || echo 'not exists'";
        $checkResult  = Helper\trim_if_string($this->execSsh($checkCommand));

        if ($checkResult === 'exists') {
            if (!$overwriteHtaccess) {
                $this->logger->info(".htaccess file already exists for domain {$domainName}. Skipping creation.");

                return true;
            } else {
                $this->logger->info(".htaccess file already exists for domain {$domainName}. Overwriting as requested.");
            }
        }

        // Define the .htaccess content for HTTPS redirection
        // Check for the presence of the REDIRECT_STATUS environment variable to avoid infinite redirects
        $htaccessContent = <<<EOF
RewriteEngine On
RewriteCond %{HTTPS}  !=on
RewriteCond %{ENV:REDIRECT_STATUS} !=200
RewriteRule ^/?(.*) https://%{HTTP_HOST}/\$1 [R=301,L]
EOF;

        // Securely add the .htaccess content to the file on the server
        // The 'EOF' is wrapped in single quotes to prevent the shell from interpreting variables.
        // This ensures that the content, including '$1', is treated as a literal string and not substituted.
        $command = sprintf(
            'cat <<\'EOF\' > %s
%s
EOF',
            $htaccessPath,
            $htaccessContent
        );
        $output = $this->execSsh($command);

        if ($output !== '') {
            $this->logger->error("Failed to create/update .htaccess for {$domainName}. Output: {$output}");

            return false;
        }

        // Retrieve the Linux user for the domain
        $username = $this->getLinuxUserForDomain($domainName);

        // Check if user retrieval was successful
        if ($username === false) {
            $this->logger->error("Did not attempt to set ownership for .htaccess due to missing Linux user for domain: {$domainName}");

            return false;
        }

        // Set the correct ownership for the .htaccess file to the domain owner
        $ownershipCommand = sprintf('chown %s:%s %s', Helper\escapeshellarg_linux($username), Helper\escapeshellarg_linux($username), $htaccessPath);
        $ownershipOutput  = $this->execSsh($ownershipCommand);

        if ($ownershipOutput !== '') {
            $this->logger->error("Failed to set ownership for .htaccess file for {$domainName}. Output: {$ownershipOutput}");

            return false;
        }

        $this->logger->info("HTTPS redirection configured for domain {$domainName} via .htaccess");

        return true;
    }

    /**
     * Creates a database for a given domain name and username on the CyberPanel server.
     *
     * @param string $domainName The domain name to be associated with the database.
     * @param string $username   The username for the database.
     * @param string $password   The password for the database user.
     *
     * @return bool True on success, false on failure.
     */
    public function createDatabase(string $domainName, string $username, string $password): bool
    {
        $cyber = $this->connectCyberLink();

        // Sanitize domain name for MySQL database name
        $dbName = Helper\sanitize_domain_for_database($domainName, $username);

        try {
            return $cyber->createDatabase($domainName, $dbName, $username, $password);
        } catch (\Exception $e) {
            // Log the exception for debugging
            $this->logger->error('Database creation failed: ' . $e->getMessage());

            return false;
        }
    }

    /**
     * Drops a database for a given domain name on the CyberPanel server.
     *
     * @param string $domainName The domain name associated with the database.
     * @param string $username   The username for the database.
     *
     * @return bool True on success, false on failure.
     */
    public function dropDatabase(string $domainName, string $username): bool
    {
        $cyber = $this->connectCyberLink();

        // Sanitize the domain name to match the created database name
        $dbName = Helper\sanitize_domain_for_database($domainName, $username);

        try {
            return $cyber->deleteDatabase($dbName);
        } catch (\Exception $e) {
            $this->logger->error('Database deletion failed: ' . $e->getMessage());

            return false;
        }
    }

    /**
     * Grants remote access to a database on the droplet.
     *
     * This method allows a specified user to connect to the database from any remote host.
     *
     * @param string $domainName The domain name associated with the database.
     * @param string $username   The username for the database.
     * @param string $password   The password for the database user.
     *
     * @throws \Exception If the SSH login fails.
     *
     * @return bool True on success, false on failure.
     */
    public function grantRemoteDatabaseAccess(string $domainName, string $username, string $password): bool
    {
        // Ensure SSH connection is established
        $this->verifyConnectionSsh();

        // Sanitize the domain name for database compatibility
        $database = Helper\sanitize_domain_for_database($domainName, $username);

        // Construct the command to grant remote access
        $grantCommand = sprintf(
            "mysql -uroot -p%s -e \"GRANT ALL PRIVILEGES ON %s.* TO '%s'@'%%' IDENTIFIED BY '%s'; FLUSH PRIVILEGES;\"",
            Helper\escapeshellarg_linux($this->config[$this->dropletName]['mysql_root_password']),
            Helper\escapeshellarg_linux($database),
            Helper\escapeshellarg_linux($username),
            Helper\escapeshellarg_linux($password)
        );

        // Execute the grant command via SSH
        try {
            $output = $this->execSsh($grantCommand);
            $this->logger->info("Remote access granted to database '{$database}' for user '{$username}'.");

            return true;
        } catch (\Exception $e) {
            $this->logger->error('Failed to grant remote access: ' . $e->getMessage());

            return false;
        }
    }

    /**
     * Changes the SSH password for a user associated with a given domain.
     *
     * Assumes sudo access to the server.
     *
     * This method connects to the server via SSH, retrieves the Linux username associated
     * with the provided domain, and attempts to change the user's password. It then
     * verifies the password change.
     *
     * @param string $domain       The domain name associated with the user account.
     * @param string $newPassword  The new password to set for the user.
     * @param bool   $verifyChange Whether to verify the password change.
     *
     * @throws \Exception If SSH connection fails or if unable to retrieve the username.
     *
     * @return bool Returns true if the password change command was executed successfully,
     *              even if verification fails. Returns false if there were errors in
     *              connection, username retrieval, or password change execution.
     */
    public function setUserPasswordSsh(string $domain, string $newPassword, bool $verifyChange = true): bool
    {
        // Ensure SSH connection is established
        $this->verifyConnectionSsh();

        $username = $this->getLinuxUserForDomain($domain);
        if (!$username) {
            $this->logger->error("Failed to retrieve username for domain: $domain");

            return false;
        }

        // Change password
        $changePasswordCommand = sprintf(
            "printf '%%s:%%s' %s %s | sudo chpasswd",
            Helper\escapeshellarg_linux($username),
            Helper\escapeshellarg_linux($newPassword)
        );
        $output = $this->execSsh($changePasswordCommand);

        if ($output === false) {
            $this->logger->error("SSH execution failed for password change command for user: $username");

            return false;
        }

        if ($output !== '') {
            $this->logger->error("Password change command failed for user: $username. Output: $output");

            return false;
        }

        $this->logger->info("Password change command executed for user: $username");

        // Verify password change
        if ($verifyChange) {
            $verifyCommand = 'sudo passwd -S ' . Helper\escapeshellarg_linux($username);
            $verifyOutput  = $this->execSsh($verifyCommand);

            // Note: We're still returning true here because the password was likely changed
            if ($verifyOutput === false) {
                $this->logger->warning("SSH execution failed for password verification command for user: $username");
            } elseif (preg_match('/^' . preg_quote($username, '/') . '\s+P\s+/', $verifyOutput) !== 1) {
                $this->logger->warning(
                    "Password change could not be verified for user: $username. Output: $verifyOutput"
                );
            } else {
                $this->logger->info("Password successfully changed for user: $username");
            }
        }

        return true;
    }

    /**
     * Enables symbolic link usage for a given domain by updating the server configuration.
     *
     * This method connects to the server via SSH and modifies the httpd_config.conf
     * file to set the "restrained" directive to 0 for the specified domain, effectively
     * enabling symbolic link usage within that domain's virtual host configuration.
     *
     * @param string $domainName The name of the domain for which symbolic links should be enabled.
     *
     * @return bool Returns true if the configuration update was successful, false otherwise.
     */
    public function enableSymlinksForDomain(string $domainName): bool
    {
        // Ensure SSH connection is established
        $this->verifyConnectionSsh();

        $filePath   = '/usr/local/lsws/conf/httpd_config.conf';
        $backupPath = $filePath . '.bak_' . date('Ymd_His');

        // Define patterns for the virtualHost block with restrained setting
        $originalPattern    = 'virtualHost[[:space:]]*' . preg_quote($domainName, '#') . '[[:space:]]*{[^}]*restrained[[:space:]]*1[^}]*}';
        $replacementPattern = 'virtualHost[[:space:]]*' . preg_quote($domainName, '#') . '[[:space:]]*{[^}]*restrained[[:space:]]*0[^}]*}';

        // Check if symlinks are already enabled (restrained = 0)
        $grepReplacementCheck = 'grep -Pzq ' . Helper\escapeshellarg_linux($replacementPattern) . " $filePath && echo 'exists'";
        $replacementCheck     = Helper\trim_if_string($this->execSsh($grepReplacementCheck));

        if ($replacementCheck === 'exists') {
            $this->logger->info("Symbolic links are already enabled for domain: $domainName");

            return true;
        }

        // Check if the original block exists (restrained = 1)
        $grepOriginalCheck = 'grep -Pzq ' . Helper\escapeshellarg_linux($originalPattern) . " $filePath && echo 'exists'";
        $originalCheck     = Helper\trim_if_string($this->execSsh($grepOriginalCheck));

        if ($originalCheck === 'exists') {
            // Create backup before making changes
            $this->logger->info("Creating backup of httpd_config.conf at: $backupPath");
            $this->execSsh("cp $filePath $backupPath");

            // Use sed to replace restrained 1 with restrained 0 within the domain's virtualHost block
            $sedRestrainedUpdate = "/virtualHost {$domainName} {/,/}/{/restrained/s#1\$#0#}";
            $sedCommand          = "sed -i '{$sedRestrainedUpdate}' $filePath";
            $sedResult           = Helper\trim_if_string($this->execSsh($sedCommand));

            if ($sedResult === false) {
                $this->logger->error("Failed to modify httpd_config.conf for domain: $domainName");

                return false;
            }

            // Verify the changes
            $verifyCommand = 'grep -Pzq ' . Helper\escapeshellarg_linux($replacementPattern) . " $filePath && echo 'updated'";
            $verifyResult  = Helper\trim_if_string($this->execSsh($verifyCommand));

            if ($verifyResult === 'updated') {
                $this->logger->info("Symbolic links successfully enabled for domain: $domainName");

                return true;
            } else {
                $this->logger->error("Failed to verify symbolic link configuration for domain: $domainName");

                return false;
            }
        } else {
            $this->logger->error("Could not find virtualHost configuration for domain: $domainName");

            return false;
        }
    }

    /**
     * Restarts the LiteSpeed web server on the server.
     *
     * This method connects to the server via SSH and executes the command to restart
     * the LiteSpeed web server.
     *
     * @return string The output of the restart command.
     */
    public function restartLiteSpeed(): string
    {
        $cyber = $this->connectCyberLink();

        $this->logger->info('Restarting LiteSpeed...');
        $result = $cyber->restartLiteSpeed();

        // Check if the result contains "[OK]" which indicates a successful restart
        if (stripos($result, '[OK]') !== false) {
            $this->logger->info('LiteSpeed restarted successfully.');
        } else {
            $this->logger->error('Failed to restart LiteSpeed.', [
                'result' => $result,
            ]);
        }

        return $result;
    }

    /**
     * Updates the nameservers on Namecheap for a given domain.
     *
     * The IP of the server this script is running on, must be whitelisted for the Namecheap API.
     * To do this, go to Account>Profile>Tools>Business & Dev Tools>Namecheap API Access>Manage.
     * And edit the Whitelisted IPs.
     *
     * @param string            $domain       The domain name to update.
     * @param array|null        $nameservers  Optional array of nameservers. Defaults to DigitalOcean's nameservers.
     * @param bool              $sandbox      Whether to use Namecheap's sandbox environment.
     * @param NamecheapApi|null $namecheapApi Optional injected NamecheapApi instance. For testing.
     * @param DomainsDns|null   $domainsDns   Optional injected DomainsDns instance. For testing.
     *
     * @return string|array|bool Returns the API response.
     */
    public function updateNameserversNamecheap(
        string $domain,
        ?array $nameservers = null,
        bool $sandbox = false,
        ?NamecheapApi $namecheapApi = null,
        ?DomainsDns $domainsDns = null
    ): string|array|bool {
        // Use the provided NamecheapApi instance, the stored instance, or create a new one
        if ($namecheapApi) {
            $this->namecheapApi = $namecheapApi;
        } elseif ($this->namecheapApi === null) {
            $user     = $username = $this->config['namecheap']['username'];
            $key      = $this->config['namecheap']['token'];
            $clientIp = '127.0.0.1';

            $this->namecheapApi = new NamecheapApi($user, $key, $username, $clientIp, 'json');
        }

        // Enable sandbox mode if requested
        if ($sandbox) {
            $this->namecheapApi->enableSandbox();
        }

        list($sld, $tld) = explode('.', $domain, 2);

        // Use the injected DomainsDns instance, or create a new one if none is provided
        $domainsDns = $domainsDns ?? new DomainsDns($this->namecheapApi);

        // Use provided nameservers or default to DigitalOcean's
        $nameservers       = $nameservers ?? ['ns1.digitalocean.com', 'ns2.digitalocean.com', 'ns3.digitalocean.com'];
        $nameserversString = implode(',', $nameservers);

        $response = $domainsDns->setCustom($sld, $tld, $nameserversString);

        // Check for errors in the API response
        if (is_string($response) || is_array($response)) {
            // Decode the response if it's a string
            $decodedResponse = is_string($response) ? json_decode($response, true) : $response;
            if (isset($decodedResponse['ApiResponse']['Errors']['Error']) || ($decodedResponse['ApiResponse']['_Status'] ?? '') === 'ERROR') {
                $errorMessage = $decodedResponse['ApiResponse']['Errors']['Error']['__text'] ?? 'Unknown error';
                $this->logger->error("Error updating nameservers for {$domain}: {$errorMessage}");
            } else {
                $this->logger->info("Successfully updated nameservers for {$domain}");
            }
        } elseif ($response === false) {
            $this->logger->error("Error updating nameservers for {$domain}: API call failed");
        } else {
            $this->logger->info("Successfully updated nameservers for {$domain}");
        }

        return $response;
    }

    /**
     * Updates the nameservers on GoDaddy for a given domain.
     *
     * @param string      $domain      The domain name to update.
     * @param array|null  $nameservers The nameservers to set. Defaults to DigitalOcean's nameservers.
     * @param Client|null $client      Optional injected Guzzle client. For testing.
     *
     * @return bool Returns true if the nameservers were updated successfully, false otherwise.
     */
    public function updateNameserversGodaddy(string $domain, ?array $nameservers = null, ?Client $client = null): bool
    {
        $nameservers = $nameservers ?? ['ns1.digitalocean.com', 'ns2.digitalocean.com', 'ns3.digitalocean.com'];

        $godaddyApiKey    = $this->config['godaddy']['api_key'] ?? null;
        $godaddyApiSecret = $this->config['godaddy']['api_secret'] ?? null;

        if (!$godaddyApiKey || !$godaddyApiSecret) {
            $this->logger->error('GoDaddy API credentials are missing from the configuration.');

            return false;
        }

        $client = $client ?? new Client([
            'base_uri' => 'https://api.godaddy.com/',
            'headers'  => [
                'Authorization' => 'sso-key ' . $godaddyApiKey . ':' . $godaddyApiSecret,
                'Content-Type'  => 'application/json',
                'Accept'        => 'application/json',
            ],
        ]);

        //$data = array_map(function ($ns) {
        //    return ['data' => $ns];
        //}, $nameservers);
        $data = [
            'nameServers' => $nameservers,
        ];

        try {
            //$response = $client->put("/v1/domains/{$domain}/records/NS/@", [
            $response = $client->patch("/v1/domains/{$domain}", [
                'json' => $data,
            ]);

            $statusCode = $response->getStatusCode();
            if ($statusCode === 200 || $statusCode === 204) {
                $this->logger->info("Nameservers updated successfully for domain {$domain}. Status code: {$statusCode}");

                return true;
            } else {
                $this->logger->error("Failed to update nameservers for domain {$domain}. Status code: {$statusCode}. Response body: " . $response->getBody());

                return false;
            }
        } catch (GuzzleException $e) {
            $this->logger->error("Error updating nameservers for domain {$domain}: " . $e->getMessage());

            return false;
        }
    }

    /**
     * Sets up a website on CyberPanel.
     *
     * @param string      $domainName    The domain name of the website to setup.
     * @param bool        $debug         Whether to output debug information.
     * @param string      $websiteEmail  The email address of the website owner.
     * @param string      $firstName     The first name of the website owner.
     * @param string      $lastName      The last name of the website owner.
     * @param string      $userEmail     The email address of the website owner.
     * @param string      $username      The username of the website owner.
     * @param string|null $password      The password for the website owner.
     * @param int         $websitesLimit The maximum number of websites the user can have.
     * @param string      $package       The package to use for the website.
     * @param string      $phpVersion    The PHP version to use for the website.
     *
     * @return void
     */
    public function setupWebsite(
        string $domainName,
        bool $debug = false,
        string $websiteEmail = 'john.doe@gmail.com',
        string $firstName = 'John',
        string $lastName = 'Doe',
        string $userEmail = 'john.doe@gmail.com',
        string $username = CyberLink::owner,
        ?string $password = null,
        int $websitesLimit = 0,
        string $package = CyberLink::package,
        string $phpVersion = CyberLink::phpVersion
    ): void {
        $websiteOwner = $username;

        if ($password === null) {
            $password = Helper\generate_password();
        }

        // Verify SSH connection
        try {
            $this->verifyConnectionSsh();
        } catch (\Throwable $th) {
            $this->logger->error('SSH connection failed: ' . $th->getMessage());
            exit;
        }

        // Configure DNS
        $this->logger->info("Configuring DNS for {$domainName}");
        $this->configureDns($domainName, $this->config[$this->dropletName]['server_ip']);
        $this->logger->info("DNS configured successfully for {$domainName}");

        // Create User
        $users = $this->getUsers(true);
        if ($username === 'admin') {
            $this->logger->info("Username is 'admin'. Not creating user.");
        } elseif (in_array($username, $users)) {
            $this->logger->info("User {$username} already exists");
        } else {
            $this->logger->info("Creating user {$username}");
            if ($this->connectCyberLink()->createUser($firstName, $lastName, $userEmail, $username, $password, $websitesLimit, $debug)) {
                $this->logger->info("User {$username} created successfully");
            } else {
                $this->logger->error("Failed to create user {$username}");
            }
        }

        // Create Website
        $websites = $this->getWebsites(true);
        if (in_array($domainName, $websites)) {
            $this->logger->info("Website {$domainName} already exists");
        } else {
            $this->logger->info("Creating website for domain {$domainName}");
            if ($this->connectCyberLink()->createWebsite($domainName, $websiteEmail, $websiteOwner, $package, $phpVersion, $debug)) {
                $this->logger->info("Website for {$domainName} created successfully");
            } else {
                $this->logger->error("Failed to create website for {$domainName}");
            }
        }

        // Redirect HTTP to HTTPS
        $this->logger->info("Redirecting {$domainName} to HTTPS");
        if ($this->createHtaccessForHttpsRedirect($domainName)) {
            $this->logger->info("HTTPS redirection configured for {$domainName}");
        } else {
            $this->logger->error("Failed to configure HTTPS redirection for {$domainName}");
        }

        // Manually issue SSL certificate
        // Even though createWebsite() has 'ssl' => 1, the HTTPS redirect in .htaccess
        // will not work, and the site will give 404 errors, unless we manually issue the SSL certificate.
        $this->logger->info("Issuing SSL certificate for {$domainName}");
        if ($this->connectCyberLink()->issueSSL($domainName, $debug)) {
            $this->logger->info("SSL certificate issued for {$domainName}");
        } else {
            $this->logger->error("Failed to issue SSL certificate for {$domainName}");
        }

        // Create Database
        $databases = $this->getDatabases($domainName);
        $dbCount   = count($databases);
        if ($dbCount > 0) {
            $this->logger->info(
                "Database(s) for {$domainName} already exist. Count: {$dbCount}.",
                ['databases' => $databases]
            );
        } else {
            $this->logger->info("Creating database for {$domainName}");
            if ($this->createDatabase($domainName, $username, $password)) {
                $this->logger->info("Database for {$domainName} created successfully");
            } else {
                $this->logger->error("Failed to create database for {$domainName}");
            }
        }

        // Enable Database External Access
        $this->logger->info("Enabling external access to the database for {$username}");
        if ($this->grantRemoteDatabaseAccess($domainName, $username, $password)) {
            $this->logger->info("External database access granted for {$username}");
        } else {
            $this->logger->error("Failed to grant external access to the database for {$username}");
        }

        // Set SFTP/SSH Access
        $this->logger->info("Setting user {$username} SSH password for domain {$domainName}");
        if ($this->setUserPasswordSsh($domainName, $password)) {
            $this->logger->info("User {$username} SSH password set for {$domainName}");
        } else {
            $this->logger->error("Failed to set {$username} SSH password for {$domainName}");
        }

        // Unrestrain Symbolic Links
        $this->logger->info("Unrestraining symbolic links for {$domainName}");
        if ($this->enableSymlinksForDomain($domainName)) {
            $this->logger->info("Symbolic links unrestrained for {$domainName}");
        } else {
            $this->logger->error("Failed to unrestrain symbolic links for {$domainName}");
        }
    }

    /**
     * Deletes a website from CyberPanel.
     *
     * @param string $domainName The domain name of the website to delete.
     * @param bool   $debug      Whether to output debug information.
     *
     * @return bool Returns true if the website was deleted successfully, false otherwise.
     */
    public function deleteWebsite(string $domainName, bool $debug = false): bool
    {
        $this->logger->info("Deleting website for {$domainName}");
        $result = $this->connectCyberLink()->deleteWebsite($domainName, $debug);
        if ($result) {
            $this->logger->info("Website for {$domainName} deleted successfully");
        } else {
            $this->logger->error("Failed to delete website for {$domainName}");
        }

        return $result;
    }

    /**
     * Updates the MySQL root password in /root/.my.cnf from /root/.db_password,
     * only if the passwords are different.
     *
     * This method retrieves the MySQL root password from /root/.db_password
     * and compares it with the current password in /root/.my.cnf. If they are
     * different, it updates /root/.my.cnf using an SSH connection.
     *
     * @throws \Exception If SSH login fails or if the update process encounters an error.
     *
     * @return bool Returns true if the password is successfully updated, false otherwise.
     */
    public function updateMyCnfPassword(): bool
    {
        // Define file paths
        $dbPasswordFile = '/root/.db_password';
        $myCnfFile      = '/root/.my.cnf';

        // Ensure SSH connection is established
        $this->verifyConnectionSsh();

        // Extract the MySQL root password from /root/.db_password
        $dbPassword = Helper\trim_if_string($this->execSsh("grep -w 'root_mysql_pass' {$dbPasswordFile} | cut -d'=' -f2 | tr -d '\"' | sed -n '1p'"));
        if (empty($dbPassword)) {
            $this->logger->error("Failed to extract the MySQL root password from {$dbPasswordFile}");

            return false;
        }

        // Extract the current password from /root/.my.cnf
        $myCnfPassword = Helper\trim_if_string($this->execSsh("grep 'password=' {$myCnfFile} | cut -d'=' -f2 | tr -d '\"' | sed -n '1p'"));
        if (empty($myCnfPassword)) {
            $this->logger->error("Failed to extract the current password from {$myCnfFile}");

            return false;
        }

        // Compare the passwords
        if ($dbPassword === $myCnfPassword) {
            $this->logger->info("The MySQL root password in {$myCnfFile} already matches the one in {$dbPasswordFile}.");

            return true;
        }

        // Backup the /root/.my.cnf file
        $backupFilename = $myCnfFile . '.bak_' . date('Ymd_His');
        $this->logger->info("Creating backup of {$myCnfFile} at: {$backupFilename}");
        $this->execSsh("cp {$myCnfFile} {$backupFilename}");

        // Update the password in /root/.my.cnf using sed
        $escapedPassword = Helper\escape_single_quotes_for_sed($dbPassword);
        $updateCommand   = "sed -i 's/password=\".*\"/password=\"$escapedPassword\"/' {$myCnfFile}";
        $output          = $this->execSsh($updateCommand);

        if ($output !== '') {
            $this->logger->error("Failed to update {$myCnfFile}. Output: {$output}");

            return false;
        }

        // Verify the password was updated correctly
        $verifiedPassword = Helper\trim_if_string($this->execSsh("grep 'password=' {$myCnfFile} | cut -d'=' -f2 | tr -d '\"' | sed -n '1p'"));
        if ($verifiedPassword !== $dbPassword) {
            $this->logger->error("Password verification failed after update. The password in {$myCnfFile} does not match {$dbPasswordFile}");

            return false;
        }

        $this->logger->info("The {$myCnfFile} password has been successfully updated and verified.");

        return true;
    }

    /**
     * Updates the Nano key binding for the "Where Is" function to Ctrl+F in /etc/nanorc.
     *
     * This method checks if the binding already exists, and if not, it updates or adds it as needed.
     * 1. If the binding is already set to Ctrl+F, it leaves it as is.
     * 2. If the binding is commented out, it un-comments it.
     * 3. If a different key is bound to "whereis all", it updates it to Ctrl+F.
     * 4. If no binding exists, it appends a new line for the binding.
     *
     * @throws \Exception If SSH connection fails or if the update process encounters an error.
     *
     * @return bool Returns true if the binding is successfully updated or already set, false otherwise.
     */
    public function updateNanoCtrlFSearchBinding(): bool
    {
        // Ensure SSH connection is established
        $this->verifyConnectionSsh();

        // Check if the binding already exists with Ctrl+F
        $existingBinding = Helper\trim_if_string($this->execSsh("grep '^bind \\^F whereis all' /etc/nanorc"));
        if ($existingBinding !== '') {
            $this->logger->info('The Nano "Where Is" binding is already set to Ctrl+F.');

            return true;
        }

        // Check if the binding is commented out
        $commentedBinding = Helper\trim_if_string($this->execSsh("grep '^#.*bind \\^F whereis all' /etc/nanorc"));
        if ($commentedBinding !== '') {
            // Uncomment the existing binding
            $uncommentCommand = "sed -i 's/^#\\s*\\(bind \\^F whereis all\\)/\\1/' /etc/nanorc";
            $output           = $this->execSsh($uncommentCommand);

            if ($output === '') {
                $this->logger->info('The Nano "Where Is" binding was commented out and has been uncommented.');

                return true;
            } else {
                $this->logger->error('Failed to uncomment the "Where Is" binding. Output: ' . $output);

                return false;
            }
        }

        // Check if another key is bound to "whereis all"
        $otherBinding = Helper\trim_if_string($this->execSsh("grep '^bind \\^[^F] whereis all' /etc/nanorc"));
        if ($otherBinding !== '') {
            // Update the binding to Ctrl+F
            $updateCommand = "sed -i 's/^bind \\^[^F] whereis all/bind \\^F whereis all/' /etc/nanorc";
            $output        = $this->execSsh($updateCommand);

            if ($output === '') {
                $this->logger->info('The Nano "Where Is" binding was updated to use Ctrl+F.');

                return true;
            } else {
                $this->logger->error('Failed to update the "Where Is" binding to Ctrl+F. Output: ' . $output);

                return false;
            }
        }

        // If no binding exists, append the new binding
        $appendCommand = "echo 'bind ^F whereis all' >> /etc/nanorc";
        $output        = $this->execSsh($appendCommand);

        if ($output === '') {
            $this->logger->info('The Nano "Where Is" binding was added with Ctrl+F.');

            return true;
        } else {
            $this->logger->error('Failed to add the "Where Is" binding with Ctrl+F. Output: ' . $output);

            return false;
        }
    }

    /**
     * Enables API access for a CyberPanel user by updating the MySQL database.
     *
     * @param string $username The username for which API access should be enabled. Defaults to 'admin'.
     *
     * @throws \Exception If SSH connection fails or command execution fails.
     *
     * @return bool True if successful, false otherwise.
     */
    public function enableCyberPanelApiAccess(string $username = 'admin'): bool
    {
        // Ensure SSH connection is established
        $this->verifyConnectionSsh();

        // Construct the SQL command to enable API access
        $mysqlRootPassword = Helper\escapeshellarg_linux($this->config[$this->dropletName]['mysql_root_password']);
        $escapedUsername   = Helper\escapeshellarg_linux($username);
        $sqlCommand        = sprintf(
            'mysql -uroot -p%s -e "UPDATE cyberpanel.loginSystem_administrator SET api = 1 WHERE userName = %s;"',
            $mysqlRootPassword,
            $escapedUsername
        );

        // Execute the SQL command via SSH
        $output = $this->execSsh($sqlCommand);

        // Check if the command was successful
        if ($output !== '') {
            $this->logger->error("Failed to enable API access for user {$username}. Output: {$output}");

            return false;
        }

        $this->logger->info("API access enabled for user {$username}");

        return true;
    }

    /**
     * Update vhost.py to modify the open_basedir replacement using grep and sed.
     *
     * @param bool $restartLiteSpeed Whether to restart LiteSpeed after updating vhost.py.
     *
     * @return bool Returns true if changes were made, false otherwise.
     */
    public function updateVhostPy($restartLiteSpeed = true): bool
    {
        // Ensure SSH connection is established
        $this->verifyConnectionSsh();

        $filePath   = '/usr/local/CyberCP/plogical/vhost.py';
        $backupPath = $filePath . '.bak_' . date('Ymd_His');

        $openBasedirOriginal    = '\'{open_basedir}\', \'php_admin_value open_basedir "/tmp:$VH_ROOT"\'';
        $openBasedirReplacement = '\'{open_basedir}\', \'php_admin_value open_basedir "/tmp:$VH_ROOT:/usr/local/lsws/share/autoindex:/proc"\'';

        // Use grep to check if the replacement line already exists
        $grepCommand           = 'grep -q ' . Helper\escapeshellarg_linux($openBasedirReplacement) . " $filePath && echo 'exists'";
        $replacementLineExists = Helper\trim_if_string($this->execSsh($grepCommand));

        // If the replacement line is already present, no changes are needed
        if ($replacementLineExists === 'exists') {
            $this->logger->info('vhost.py already contains the replacement line. No changes needed.');

            return true;
        }

        // Else check if the original line exists
        $grepCommand        = 'grep -q ' . Helper\escapeshellarg_linux($openBasedirOriginal) . " $filePath && echo 'exists'";
        $originalLineExists = Helper\trim_if_string($this->execSsh($grepCommand));

        // If the original line is present, back up the file and replace the line
        if ($originalLineExists === 'exists') {
            $this->logger->info("Creating backup of vhost.py at: $backupPath");
            $this->execSsh("cp $filePath $backupPath");

            // Use sed to replace the original line with the replacement line
            $sedOriginal    = Helper\escape_single_quotes_for_sed($openBasedirOriginal);
            $sedReplacement = Helper\escape_single_quotes_for_sed($openBasedirReplacement);
            $sedCommand     = "sed -i 's#{$sedOriginal}#{$sedReplacement}#' $filePath";
            $this->logger->info("Executing sed command: $sedCommand");
            $this->execSsh($sedCommand);

            // Use grep to verify the replacement
            $grepCommand       = 'grep -q ' . Helper\escapeshellarg_linux($openBasedirReplacement) . " $filePath && echo 'updated'";
            $verificationCheck = Helper\trim_if_string($this->execSsh($grepCommand));

            if ($verificationCheck === 'updated') {
                $this->logger->info('vhost.py updated successfully.');

                // Restart OpenLiteSpeed if required
                if ($restartLiteSpeed) {
                    $this->restartLiteSpeed();
                }

                return true;
            } else {
                $this->logger->error('Failed to verify the replacement in vhost.py.');

                return false;
            }
        } else {
            $this->logger->error('vhost.py does not contain the original line to modify. Replacement not possible.');

            return false;
        }
    }

    /**
     * Updates the vhostConfs.py file by modifying the 'index' block with varying whitespace.
     *
     * @param bool $restartLiteSpeed Whether to restart LiteSpeed after updating the file.
     *
     * @return bool True if the update is successful, false otherwise.
     */
    public function updateVhostConfsPy(bool $restartLiteSpeed = true): bool
    {
        // Ensure SSH connection is established
        $this->verifyConnectionSsh();

        // File path
        $filePath   = '/usr/local/CyberCP/plogical/vhostConfs.py';
        $backupPath = $filePath . '.bak_' . date('Ymd_His');

        // Use regex patterns to handle varying whitespace
        // sed can not handle \s for whitespace, so we use [:space:] instead
        $originalPattern    = 'index[[:space:]]*{[[:space:]]*useServer[[:space:]]*0[[:space:]]*indexFiles[[:space:]]*index\.php,[[:space:]]*index\.html[[:space:]]*}';
        $replacementPattern = 'index[[:space:]]*{[[:space:]]*'
            . 'useServer[[:space:]]*1[[:space:]]*'
            . 'indexFiles[[:space:]]*index\.php,[[:space:]]*index\.html[[:space:]]*'
            . 'autoIndex[[:space:]]*1[[:space:]]*}';
        $replacementBlock = 'index  {\
  useServer               1\
  indexFiles              index.php, index.html\
  autoIndex               1\
}';

        // Check if the replacement has already been made
        // -P is for Perl regex, -z is for multi-line, -q is for quiet mode
        $grepReplacementCheck = 'grep -Pzq ' . Helper\escapeshellarg_linux($replacementPattern) . " $filePath && echo 'exists'";
        $replacementCheck     = Helper\trim_if_string($this->execSsh($grepReplacementCheck));

        if ($replacementCheck === 'exists') {
            // Replacement already exists
            $this->logger->info('Replacement already exists in vhostConfs.py.');

            return true;
        }

        // Check if the original block is present using regex with sed
        $grepOriginalCheck = 'grep -Pzq ' . Helper\escapeshellarg_linux($originalPattern) . " $filePath && echo 'exists'";
        $originalCheck     = Helper\trim_if_string($this->execSsh($grepOriginalCheck));

        if ($originalCheck === 'exists') {
            // Back up the original file
            $this->logger->info("Creating backup of $filePath at: $backupPath");
            $backupCommand = "cp $filePath $backupPath";
            $this->execSsh($backupCommand);

            // Replace the block using sed with regex support
            $sedOriginal    = Helper\escape_single_quotes_for_sed($originalPattern);
            $sedReplacement = Helper\escape_single_quotes_for_sed($replacementBlock);
            // Use -z to handle multi-line replacement
            $sedCommand = "sed -i -z 's#{$sedOriginal}#{$sedReplacement}#' $filePath";
            // Use Helper\trim_if_string(), as trim(false) gives an empty string instead of a Boolean false
            $sedResult = Helper\trim_if_string($this->execSsh($sedCommand));

            if ($sedResult === false) {
                $this->logger->error('Failed to modify vhostConfs.py.');

                return false;
            }

            // Verify the replacement
            $verifyCommand = 'grep -Pzq ' . Helper\escapeshellarg_linux($replacementPattern) . " $filePath && echo 'updated'";
            $verifyResult  = Helper\trim_if_string($this->execSsh($verifyCommand));

            if ($verifyResult === 'updated') {
                $this->logger->info('vhostConfs.py updated successfully.');
                if ($restartLiteSpeed) {
                    $this->restartLiteSpeed();
                }

                return true;
            } else {
                $this->logger->error('Failed to verify the modification in vhostConfs.py.');

                return false;
            }
        } else {
            $this->logger->error('vhostConfs.py does not contain the original section to modify. Replacement not possible.');

            return false;
        }
    }

    /**
     * Sets up aliases and functions via SSH, if not already present.
     *
     * @return bool Returns true if all operations were successful, false otherwise
     */
    public function setupAliasesAndFunctions(): bool
    {
        // Ensure SSH connection is established
        $this->verifyConnectionSsh();

        $success = true;

        $entries = [
            // Find directories, sorted alphabetically ignoring case, remove leading ./
            'alias dfind="find -maxdepth 1 -type d | sort -f | sed \'\\\'\'s/.\///g\'\\\'\'"' => '/etc/profile.d/z-alias-dfind.sh',
            // Disk usage, in MB, max depth 1
            'alias du1="du -B MB --max-depth=1"' => '/etc/profile.d/z-alias-du1.sh',
            // Find files, sorted alphabetically ignoring case, remove leading ./
            'alias ffind="find -maxdepth 1 -type f | sort -f | sed \'\\\'\'s/.\///g\'\\\'\'"' => '/etc/profile.d/z-alias-ffind.sh',
            // List files (including hidden) with details, human readable file size, colorized
            'alias ll="ls -alhF --color=auto"' => '/etc/profile.d/z-alias-ll.sh',
            // List files, colorized
            'alias ls="ls --color=auto"' => '/etc/profile.d/z-alias-ls.sh',
            // Ask for confirmation before removing files
            'alias rm="rm -i"' => '/etc/profile.d/z-alias-rm.sh',
            // Switch to user with full login
            'alias su="su -"' => '/etc/profile.d/z-alias-su.sh',
            // Column output, table format, tab separator, less output
            'colu() { column -t -s$\'\\t\' $1 | less -S; }' => '/etc/profile.d/z-function-colu.sh',
            // Disk usage, in MB, max depth set by first argument, default is 1
            'dun() { du -B MB --max-depth="${1:-1}"; }' => '/etc/profile.d/z-function-dun.sh',
            // In-line grep, recursive to subdirectories, case insensitive, whole word, ignore case
            // Recursively searches for a case-insensitive, whole-word match of the provided pattern(s) in the current directory, showing line numbers
            'ingrep() { grep -rnwi . -e "$*"; }' => '/etc/profile.d/z-function-ingrep.sh',
            // Search for directories by name from root, print the directory path,
            // and list its contents with detailed, human-readable output.
            'lsfind() { find / -name "$1" -type d -exec sh -c \'\\\'\'echo "\nDirectory: {}"; ls -alh "{}"\'\\\'\' \; ; }' => '/etc/profile.d/z-function-lsfind.sh',
            // PHP, filename, name, php, pipe output to tee with _tee.out suffix
            'phptee() { filename="$1"; name="${filename%.*}"; php $name.php |& tee ${name}_tee.out; }' => '/etc/profile.d/z-function-phptee.sh',
        ];

        foreach ($entries as $entry => $filePath) {
            // Check if the file already exists
            $fileExists = $this->execSsh("[ -f $filePath ] && echo 'exists'");

            if (Helper\trim_if_string($fileExists) === 'exists') {
                $this->logger->info("File $filePath already exists. Skipping.");

                continue;
            }

            // Create the alias/function file
            $command = "echo '$entry' > $filePath && echo 'created'";
            $result  = $this->execSsh($command);

            if (Helper\trim_if_string($result) === 'created') {
                $this->logger->info("Successfully created $filePath.");
            } else {
                $this->logger->error("Failed to create $filePath. Command: $command SSH output: $result");
                $success = false;
            }
        }

        $this->logger->info('Shell aliases and functions setup process completed.');

        return $success;
    }

    /**
     * Configures the screen utility by updating /etc/screenrc with specific settings.
     *
     * This method configures three settings in the screenrc file:
     * 1. Disables the startup message
     * 2. Enables mouse scrolling in xterm
     * 3. Sets the default shell to bash
     *
     * @return bool Returns true if all configurations were successful, false otherwise.
     */
    public function configureScreen(): bool
    {
        // Ensure SSH connection is established
        $this->verifyConnectionSsh();

        $filePath   = '/etc/screenrc';
        $backupPath = $filePath . '.bak_' . date('Ymd_His');
        $success    = true;

        // Backup the original file
        $this->logger->info("Backing up $filePath to $backupPath");
        $this->execSsh("cp $filePath $backupPath");

        // Define the configurations to be added/updated
        $configurations = [
            'startup_message off',
            'termcapinfo xterm|xterms|xs|rxvt ti@:te@',
            'shell -/bin/bash',
        ];

        foreach ($configurations as $pattern) {
            // Check if the exact line already exists
            $grepPattern = "grep -q '^{$pattern}$' {$filePath} && echo 'exists'";
            $grepCheck   = Helper\trim_if_string($this->execSsh($grepPattern));
            if ($grepCheck !== 'exists') {
                // Check if the commented version exists
                $grepCommentedPattern = "grep -q '^#{$pattern}$' {$filePath} && echo 'exists'";
                if (Helper\trim_if_string($this->execSsh($grepCommentedPattern)) === 'exists') {
                    // Replace the commented version with uncommented
                    $sedCommand = "sed -i 's/^#{$pattern}$/{$pattern}/' {$filePath}";
                    $this->logger->info("Replacing commented version of {$pattern} with uncommented");
                    $this->execSsh($sedCommand);
                } else {
                    // Append new line
                    $this->logger->info("Appending new line: {$pattern}");
                    $this->execSsh("echo '{$pattern}' >> {$filePath}");
                }

                // Verify the change
                $verificationCheck = Helper\trim_if_string($this->execSsh($grepPattern));
                if ($verificationCheck !== 'exists') {
                    $this->logger->error("Failed to configure {$pattern} in screenrc");
                    $success = false;
                } else {
                    $this->logger->info("Successfully configured {$pattern} in screenrc");
                }
            } else {
                $this->logger->info("{$pattern} already configured in screenrc");
            }
        }

        return $success;
    }

    /**
     * Updates CyberPanel using a noninteractive shell.
     *
     * This method performs a system update of CyberPanel using the official preUpgrade script
     * in a noninteractive way. It prevents interactive prompts and executes the update script
     * with appropriate timeouts.
     *
     * @param bool $updateOs   Whether to also update the operating system packages
     * @param bool $pipInstall Whether to also pip install. See link.
     * @param int  $timeout    SSH timeout in seconds (default: 3600 = 1 hour)
     *
     * @return bool Returns true if the update was successful, false otherwise
     *
     * @link https://community.cyberpanel.net/t/pyxattr-error-updating-cyberpanel/54460/5
     */
    public function updateCyberPanel(bool $updateOs = true, bool $pipInstall = true, int $timeout = 3600): bool
    {
        // Ensure SSH connection is established
        $this->verifyConnectionSsh();

        $pipFile = '/usr/local/requirments.txt';

        try {
            // Store the original timeout
            $originalTimeout = $this->sshConnection->getTimeout();

            // Set a longer timeout for the update process
            $this->sshConnection->setTimeout($timeout);

            if ($updateOs) {
                // Update OS packages first
                $this->logger->info('Updating operating system packages...');

                // Execute update and upgrade separately, since executeCommand() will not work
                // with && and self::NONINTERACTIVE_SHELL
                if (!$this->executeCommand('apt-get update')) {
                    $this->logger->error('Failed to update package lists');

                    return false;
                }

                if (!$this->executeCommand('apt-get -y upgrade')) {
                    $this->logger->error('Failed to upgrade packages');

                    return false;
                }

                $this->logger->info('OS packages updated successfully');
            }

            if ($pipInstall) {
                // Check if the pip file exists
                if (!$this->executeCommand("test -f $pipFile")) {
                    $this->logger->error("Pip file $pipFile does not exist. Not installing pip.");
                } else {
                    $this->logger->info('Installing pip...');

                    if (!$this->executeCommand("pip install -r $pipFile --ignore-installed")) {
                        $this->logger->error('Failed to install pip');

                        return false;
                    }

                    $this->logger->info('pip installed successfully');
                }
            }

            // Run the official preUpgrade script
            $this->logger->info('Running CyberPanel update script...');
            $updateCommand = 'sh <(curl https://raw.githubusercontent.com/usmannasir/cyberpanel/stable/preUpgrade.sh || wget -O - https://raw.githubusercontent.com/usmannasir/cyberpanel/stable/preUpgrade.sh)';

            if (!$this->executeCommand($updateCommand)) {
                $this->logger->error('Failed to run CyberPanel update script');

                return false;
            }

            $this->logger->info('CyberPanel update completed successfully');

            return true;
        } catch (\Exception $e) {
            $this->logger->error('Error during CyberPanel update: ' . $e->getMessage());

            return false;
        } finally {
            // Restore the original timeout if it was changed
            if (isset($originalTimeout)) {
                $this->sshConnection->setTimeout($originalTimeout);
            }
        }
    }

    /**
     * Installs and configures multiple PHP versions with extensions.
     *
     * This method:
     * 1. Adds the Ondřej Surý PPA for PHP
     * 2. Installs PHP 8.2 and 8.3 core packages
     * 3. Installs/upgrades specified extensions for PHP 7.4-8.3
     * 4. Optionally sets a default PHP version
     *
     * @param bool        $updateApt         Whether to run apt-get update before installation
     * @param int         $timeout           SSH timeout in seconds (default: 1800 = 30 minutes)
     * @param string|null $defaultPhpVersion PHP version to set as default (e.g., '8.3')
     *
     * @throws \InvalidArgumentException If an invalid PHP version is provided
     * @throws \Exception                If SSH connection fails or commands cannot be executed
     *
     * @return bool Returns true if all operations were successful, false otherwise
     */
    public function installPhpVersionsAndExtensions(bool $updateApt = true, int $timeout = 1800, ?string $defaultPhpVersion = '8.3'): bool
    {
        // Ensure SSH connection is established
        $this->verifyConnectionSsh();

        try {
            // Store and set timeout
            $originalTimeout = $this->sshConnection->getTimeout();
            $this->sshConnection->setTimeout($timeout);

            // Define a shared list of extensions (without json)
            $sharedExtensions = [
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
            ];

            // Define PHP versions and their extensions, adding `json` only for PHP 7.4
            $phpExtensions = [
                '7.4' => array_merge($sharedExtensions, ['json']),
                '8.0' => $sharedExtensions,
                '8.1' => $sharedExtensions,
                '8.2' => $sharedExtensions,
                '8.3' => $sharedExtensions,
            ];

            // Validate default PHP version if provided
            if ($defaultPhpVersion !== null && !array_key_exists($defaultPhpVersion, $phpExtensions)) {
                throw new \InvalidArgumentException("Invalid PHP version: $defaultPhpVersion");
            }

            // Add PHP repository and update
            $commands = [
                'sudo add-apt-repository -y ppa:ondrej/php',
            ];

            if ($updateApt) {
                $commands[] = 'sudo apt-get update';
            }

            foreach ($commands as $command) {
                $this->logger->info("Executing command: $command");
                if (!$this->executeCommand($command)) {
                    return false;
                }
            }

            // Install PHP 8.2 and 8.3 core
            $this->logger->info('Installing PHP 8.2 and 8.3 core packages...');
            if (!$this->executeCommand('sudo apt-get install -y php8.2 php8.3')) {
                return false;
            }

            // Install/upgrade extensions for each PHP version
            foreach ($phpExtensions as $version => $extensions) {
                $this->logger->info("Installing/upgrading extensions for PHP $version...");

                // Build extension packages string
                $extensionPackagesArray = [];
                foreach ($extensions as $ext) {
                    $extensionPackagesArray[] = "php$version-$ext";
                }
                $extensionPackages = implode(' ', $extensionPackagesArray);

                if (!$this->executeCommand("sudo apt-get install -y $extensionPackages")) {
                    return false;
                }

                $this->logger->info("Completed extensions for PHP $version");
            }

            // Set default PHP version if specified
            if ($defaultPhpVersion) {
                $this->logger->info("Setting PHP $defaultPhpVersion as default...");

                // First, configure the alternatives
                if (!$this->executeCommand(
                    "sudo update-alternatives --install /usr/bin/php php /usr/bin/php$defaultPhpVersion 1"
                )) {
                    return false;
                }

                // Then set it as default
                if (!$this->executeCommand(
                    "sudo update-alternatives --set php /usr/bin/php$defaultPhpVersion"
                )) {
                    return false;
                }

                $this->logger->info("PHP $defaultPhpVersion set as default version");
            }

            $this->logger->info('PHP installation and configuration completed successfully');

            return true;
        } catch (\InvalidArgumentException $e) {
            // Rethrow InvalidArgumentException
            throw $e;
        } catch (\Exception $e) {
            $this->logger->error('Error during PHP installation: ' . $e->getMessage());

            return false;
        } finally {
            // Restore original timeout
            if (isset($originalTimeout)) {
                $this->sshConnection->setTimeout($originalTimeout);
            }
        }
    }

    /**
     * Executes a command on the SSH connection and logs the result if debugging is enabled.
     *
     * @param string  $command The command to execute
     * @param ?string $context The context of the command execution, for logging purposes
     *
     * @return mixed The result of the command execution
     */
    private function execSsh(string $command, ?string $context = null): mixed
    {
        // Ensure SSH connection is established
        $this->verifyConnectionSsh();

        $result = $this->sshConnection->exec($command);

        if ($this->debug) {
            echo PHP_EOL . "execSsh({$command}, {$context}):" . PHP_EOL;
            var_dump($result);
        }

        return $result;
    }

    /**
     * Executes a shell command with NONINTERACTIVE_SHELL prefix and captures the exit code.
     *
     * @param string $command The command to execute
     *
     * @return bool True if command executed successfully (exit code 0), false otherwise
     */
    private function executeCommand(string $command): bool
    {
        // Append stderr redirection and capture exit code with distinct delimiters
        $fullCommand = self::NONINTERACTIVE_SHELL . ' ' . $command .
            ' 2>&1; echo "<<<EXITCODE_DELIMITER>>>$?<<<EXITCODE_END>>>"';

        // Execute the command, capture the output, and trim_if_string() it
        $output = Helper\trim_if_string($this->sshConnection->exec($fullCommand));

        if ($this->debug) {
            echo PHP_EOL . "executeCommand({$command}):" . PHP_EOL;
            var_dump($output);
        }

        if ($output === false) {
            $this->logger->error(
                'SSH execution failed for command: ' . $command
            );

            return false;
        }

        // Extract exit code from output using regex
        $pregResult = preg_match('/<<<EXITCODE_DELIMITER>>>(\d+)<<<EXITCODE_END>>>$/', $output, $matches);

        if ($this->debug) {
            echo 'matches:' . PHP_EOL;
            var_dump($matches);
        }

        if ($pregResult) {
            $exitCode = (int) $matches[1];
            // Remove exit code delimiter pattern from output
            $output = preg_replace('/<<<EXITCODE_DELIMITER>>>\d+<<<EXITCODE_END>>>$/', '', $output);

            if ($this->debug) {
                echo "exitCode: {$exitCode}" . PHP_EOL;
                echo 'output:' . PHP_EOL;
                var_dump($output);
            }
        } else {
            $this->logger->error(
                'Failed to get exit code for command: ' . $command,
                ['output' => $output]
            );

            return false;
        }

        if ($exitCode !== 0) {
            $this->logger->error(
                'Command failed with exit code ' . $exitCode . ': ' . $command,
                ['output' => $output]
            );

            return false;
        }

        if ($this->verbose && !empty($output)) {
            $this->logger->info(
                'Command output: ' . $command,
                ['output' => $output]
            );
        }

        return true;
    }

    /**
     * Installs LiteSpeed PHP versions and extensions.
     *
     * This method:
     * - Optionally updates apt packages
     * - Validates requested PHP versions
     * - Installs specified LiteSpeed PHP versions and their extensions
     *
     * @param bool       $updateApt Whether to run apt-get update before installation
     * @param int        $timeout   SSH timeout in seconds (default: 1800 = 30 minutes)
     * @param array|null $versions  Array of PHP versions to install (e.g., ['7.4', '8.3'])
     *                              If null, installs all supported versions
     *
     * @throws \InvalidArgumentException If an invalid PHP version is provided
     * @throws \Exception                If SSH connection fails or commands cannot be executed
     *
     * @return bool Returns true if all operations were successful, false otherwise
     */
    public function installLiteSpeedPhpVersionsAndExtensions(bool $updateApt = true, int $timeout = 1800, ?array $versions = null): bool
    {
        // Ensure SSH connection is established
        $this->verifyConnectionSsh();

        try {
            // Store and set timeout
            $originalTimeout = $this->sshConnection->getTimeout();
            $this->sshConnection->setTimeout($timeout);

            // Define supported PHP versions and their extensions
            $supportedVersions = [
                '7.4' => [
                    '', // Empty string for base package
                    'apcu',
                    'common',
                    'curl',
                    'dbg',
                    'dev',
                    'igbinary',
                    'imagick',
                    'imap',
                    'intl',
                    'ioncube',
                    'json',
                    'ldap',
                    'memcached',
                    'modules-source',
                    'msgpack',
                    'mysql',
                    'opcache',
                    'pear',
                    'pgsql',
                    'pspell',
                    'redis',
                    'snmp',
                    'sqlite3',
                    'sybase',
                    'tidy',
                ],
                '8.0' => [
                    '',
                    'apcu',
                    'common',
                    'curl',
                    'dbg',
                    'dev',
                    'igbinary',
                    'imagick',
                    'imap',
                    'intl',
                    'ldap',
                    'memcached',
                    'modules-source',
                    'msgpack',
                    'mysql',
                    'opcache',
                    'pear',
                    'pgsql',
                    'pspell',
                    'redis',
                    'snmp',
                    'sqlite3',
                    'sybase',
                    'tidy',
                ],
                '8.1' => [
                    '',
                    'apcu',
                    'common',
                    'curl',
                    'dbg',
                    'dev',
                    'igbinary',
                    'imagick',
                    'imap',
                    'intl',
                    'ioncube',
                    'ldap',
                    'memcached',
                    'modules-source',
                    'msgpack',
                    'mysql',
                    'opcache',
                    'pear',
                    'pgsql',
                    'pspell',
                    'redis',
                    'snmp',
                    'sqlite3',
                    'sybase',
                    'tidy',
                ],
                '8.2' => [
                    '',
                    'apcu',
                    'common',
                    'curl',
                    'dbg',
                    'dev',
                    'igbinary',
                    'imagick',
                    'imap',
                    'intl',
                    'ioncube',
                    'ldap',
                    'memcached',
                    'modules-source',
                    'msgpack',
                    'mysql',
                    'opcache',
                    'pear',
                    'pgsql',
                    'pspell',
                    'redis',
                    'snmp',
                    'sqlite3',
                    'sybase',
                    'tidy',
                ],
                '8.3' => [
                    '',
                    'apcu',
                    'common',
                    'curl',
                    'dbg',
                    'dev',
                    'igbinary',
                    'imagick',
                    'imap',
                    'intl',
                    'ioncube',
                    'ldap',
                    'memcached',
                    'modules-source',
                    'msgpack',
                    'mysql',
                    'opcache',
                    'pear',
                    'pgsql',
                    'pspell',
                    'redis',
                    'snmp',
                    'sqlite3',
                    'sybase',
                    'tidy',
                ],
            ];

            // If no versions specified, install all supported versions
            $versions = $versions ?? array_keys($supportedVersions);

            // Validate requested versions
            foreach ($versions as $version) {
                if (!isset($supportedVersions[$version])) {
                    throw new \InvalidArgumentException("Invalid PHP version: $version");
                }
            }

            // Update package lists if requested
            if ($updateApt) {
                $this->logger->info('Updating package lists...');
                if (!$this->executeCommand('apt-get update')) {
                    return false;
                }
            }

            // Build installation command for each version
            foreach ($versions as $version) {
                $shortVersion = str_replace('.', '', $version);
                $this->logger->info("Installing LiteSpeed PHP $version and extensions...");

                // Build package list for this version
                $packages = [];
                foreach ($supportedVersions[$version] as $extension) {
                    $packageName = "lsphp{$shortVersion}" . ($extension ? "-{$extension}" : '');
                    $packages[]  = $packageName;
                }

                // Create installation command
                $installCommand = 'apt-get install -y ' . implode(' ', $packages);

                // Execute installation
                if (!$this->executeCommand($installCommand)) {
                    $this->logger->error("Failed to install LiteSpeed PHP $version packages");

                    return false;
                }

                $this->logger->info("Successfully installed LiteSpeed PHP $version and extensions");
            }

            $this->logger->info('LiteSpeed PHP installation completed successfully');

            return true;
        } catch (\InvalidArgumentException $e) {
            // Rethrow InvalidArgumentException
            throw $e;
        } catch (\Exception $e) {
            $this->logger->error('Error during LiteSpeed PHP installation: ' . $e->getMessage());

            return false;
        } finally {
            // Restore original timeout
            if (isset($originalTimeout)) {
                $this->sshConnection->setTimeout($originalTimeout);
            }
        }
    }

    /**
     * Configures PHP by creating symlinks and optionally enabling display errors.
     *
     * This method:
     * 1. Creates symlinks for PHP versions 7.4 to 8.3
     * 2. Optionally enables display_errors in php.ini for each version
     *
     * @param bool $enableDisplayErrors Whether to enable display_errors in php.ini
     *
     * @return bool Returns true if all operations were successful, false otherwise
     */
    public function configurePhp(bool $enableDisplayErrors = false): bool
    {
        // Ensure SSH connection is established
        $this->verifyConnectionSsh();

        $success = true;

        // Define PHP versions and their paths
        $phpVersions = [
            '74' => '7.4',
            '80' => '8.0',
            '81' => '8.1',
            '82' => '8.2',
            '83' => '8.3',
        ];

        // Create symlinks for each PHP version
        foreach ($phpVersions as $shortVersion => $fullVersion) {
            $sourcePath = "/usr/local/lsws/lsphp{$shortVersion}/bin/php";
            $targetPath = "/usr/bin/php{$fullVersion}";

            // Check if symlink or file already exists
            $checkCommand  = "test -e {$targetPath} && echo 'exists'";
            $symlinkExists = Helper\trim_if_string($this->execSsh($checkCommand, 'configurePhp'));

            if ($symlinkExists === 'exists') {
                $this->logger->info("Symlink for PHP {$fullVersion} already exists");

                continue;
            }

            // Create symlink
            if (!$this->executeCommand("ln -s {$sourcePath} {$targetPath}")) {
                $this->logger->error("Failed to create symlink for PHP {$fullVersion}");
                $success = false;

                continue;
            }

            $this->logger->info("Created symlink for PHP {$fullVersion}");
        }

        // Enable display errors if requested
        if ($enableDisplayErrors) {
            foreach ($phpVersions as $shortVersion => $fullVersion) {
                $phpIniPath = "/usr/local/lsws/lsphp{$shortVersion}/etc/php/{$fullVersion}/litespeed/php.ini";
                $this->logger->info("Checking display errors for PHP {$fullVersion} at {$phpIniPath}");

                // Check if display_errors is already On
                $grepOnCommand   = "grep -i '^display_errors[[:space:]]*=[[:space:]]*On' {$phpIniPath}";
                $displayErrorsOn = Helper\trim_if_string($this->execSsh($grepOnCommand, 'configurePhp'));

                if (!empty($displayErrorsOn)) {
                    $this->logger->info("Display errors already enabled for PHP {$fullVersion}");

                    continue;
                }

                // Check if display_errors = Off exists
                $grepOffCommand   = "grep -i '^display_errors[[:space:]]*=[[:space:]]*Off' {$phpIniPath}";
                $displayErrorsOff = Helper\trim_if_string($this->execSsh($grepOffCommand, 'configurePhp'));

                if (empty($displayErrorsOff)) {
                    $this->logger->error("Could not find display_errors = Off line in {$phpIniPath}. Skipping enabling display errors for PHP {$fullVersion}.");
                    $success = false;

                    continue;
                }

                // Create backup of php.ini
                $backupPath = $phpIniPath . '.bak_' . date('Ymd_His');
                $this->logger->info("Creating backup of {$phpIniPath} at {$backupPath}");
                if (!$this->executeCommand("cp {$phpIniPath} {$backupPath}")) {
                    $this->logger->error("Failed to create backup of php.ini for PHP {$fullVersion}");
                    $success = false;

                    continue;
                }

                // Replace display_errors = Off with display_errors = On
                $sedCommand = "sed -i 's/^display_errors[[:space:]]*=[[:space:]]*Off/display_errors = On/I' {$phpIniPath}";
                if (!$this->executeCommand($sedCommand)) {
                    $this->logger->error("Failed to enable display errors for PHP {$fullVersion}");
                    $success = false;

                    continue;
                }

                // Verify the change
                $verifyCommand = "grep -i '^display_errors[[:space:]]*=[[:space:]]*On' {$phpIniPath}";
                $verifyResult  = Helper\trim_if_string($this->execSsh($verifyCommand, 'configurePhp'));

                if (empty($verifyResult)) {
                    $this->logger->error("Failed to verify display errors setting for PHP {$fullVersion}");
                    $success = false;
                } else {
                    $this->logger->info("Successfully enabled display errors for PHP {$fullVersion}");
                }
            }
        }

        return $success;
    }

    /**
     * Configures MySQL to enable external access by modifying /etc/mysql/my.cnf.
     *
     * This method:
     * - Creates a backup of the original file
     * - Ensures [mysqld] section exists
     * - Sets skip-networking=0
     * - Adds skip-bind-address
     *
     * @return bool Returns true if all configurations were successful, false otherwise
     */
    public function configureMySql(): bool
    {
        // Ensure SSH connection is established
        $this->verifyConnectionSsh();

        $filePath   = '/etc/mysql/my.cnf';
        $backupPath = $filePath . '.bak_' . date('Ymd_His');

        // Create backup
        $this->logger->info("Creating backup of my.cnf at: $backupPath");
        $this->execSsh("cp $filePath $backupPath");

        // Check for [mysqld] section
        $mysqldCheck = Helper\trim_if_string($this->execSsh("grep -qx '\\[mysqld\\]' $filePath && echo 'exists'"));
        if ($mysqldCheck !== 'exists') {
            $this->logger->info('Adding [mysqld] section');
            $this->execSsh("echo '\n[mysqld]' >> $filePath");

            // Verify addition
            $verifyMysqld = Helper\trim_if_string($this->execSsh("grep -qx '\\[mysqld\\]' $filePath && echo 'exists'"));
            if ($verifyMysqld !== 'exists') {
                $this->logger->error('Failed to add [mysqld] section');

                return false;
            }
        }

        // Handle skip-networking
        $skipNetworkingCheck = Helper\trim_if_string($this->execSsh("grep -qi '^skip-networking' $filePath && echo 'exists'"));
        if ($skipNetworkingCheck !== 'exists') {
            $this->logger->info('Adding skip-networking=0');
            $this->execSsh("echo 'skip-networking=0' >> $filePath");
        } else {
            $skipNetworkingZeroCheck = Helper\trim_if_string($this->execSsh("grep -qi '^skip-networking=0' $filePath && echo 'exists'"));
            if ($skipNetworkingZeroCheck !== 'exists') {
                $this->logger->info('Updating existing skip-networking to 0');
                // Handle all possible variations: skip-networking, skip-networking=1, skip-networking=ON, etc.
                $this->execSsh("sed -i 's/^skip-networking.*/skip-networking=0/i' $filePath");
            }
        }

        // Verify skip-networking
        $verifySkipNetworking = Helper\trim_if_string($this->execSsh("grep -qi '^skip-networking=0' $filePath && echo 'exists'"));
        if ($verifySkipNetworking !== 'exists') {
            $this->logger->error('Failed to configure skip-networking');

            return false;
        }

        // Handle skip-bind-address
        $skipBindCheck = Helper\trim_if_string($this->execSsh("grep -qx 'skip-bind-address' $filePath && echo 'exists'"));
        if ($skipBindCheck !== 'exists') {
            $this->logger->info('Adding skip-bind-address');
            $this->execSsh("echo 'skip-bind-address' >> $filePath");

            // Verify addition
            $verifySkipBind = Helper\trim_if_string($this->execSsh("grep -qx 'skip-bind-address' $filePath && echo 'exists'"));
            if ($verifySkipBind !== 'exists') {
                $this->logger->error('Failed to add skip-bind-address');

                return false;
            }
        }

        // After all configurations are done, restart MySQL
        $this->logger->info('Restarting MySQL service...');
        if (!$this->executeCommand('systemctl restart mysql')) {
            $this->logger->error('Failed to restart MySQL service');

            return false;
        }

        // Verify MySQL is running
        if (!$this->executeCommand('service mysql status')) {
            $this->logger->error('MySQL service failed to start');

            return false;
        }

        $this->logger->info('MySQL configuration completed successfully');

        return true;
    }

    /**
     * Opens a specified port on the firewall and reloads it.
     *
     * This method:
     * - Checks if the port is already open
     * - Adds the port to the firewall if not already open
     * - Reloads the firewall to apply changes
     *
     * @param int $port The port number to open (default: 3306)
     *
     * @return bool Returns true if the port was successfully opened or was already open,
     *              false if the operation failed
     */
    public function openFirewall(int $port = 3306): bool
    {
        // Ensure SSH connection is established
        $this->verifyConnectionSsh();

        // Check if port is already open
        $checkCommand = "firewall-cmd --list-ports | grep '$port/tcp'";
        $portStatus   = Helper\trim_if_string($this->execSsh($checkCommand));

        if (!empty($portStatus)) {
            $this->logger->info("Port $port is already open in the firewall");

            return true;
        }

        // Add the port to the firewall permanently
        $this->logger->info("Opening port $port in the firewall...");
        if (!$this->executeCommand("firewall-cmd --permanent --zone=public --add-port=$port/tcp")) {
            $this->logger->error("Failed to open port $port in the firewall");

            return false;
        }

        // Reload the firewall
        $this->logger->info('Reloading firewall...');
        if (!$this->executeCommand('firewall-cmd --reload')) {
            $this->logger->error('Failed to reload the firewall');

            return false;
        }

        // Verify the port is now open
        $verifyCommand = "firewall-cmd --list-ports | grep '$port/tcp'";
        $verifyStatus  = Helper\trim_if_string($this->execSsh($verifyCommand));

        if (empty($verifyStatus)) {
            $this->logger->error("Failed to verify port $port is open in the firewall");

            return false;
        }

        $this->logger->info("Successfully opened port $port in the firewall");

        return true;
    }

    /**
     * Downloads and installs WP-CLI on the server.
     *
     * This method:
     * - Downloads WP-CLI to /tmp
     * - Verifies the download
     * - Makes it executable
     * - Moves it to /usr/local/bin
     * - Verifies the installation
     *
     * @return bool Returns true if WP-CLI was successfully installed, false otherwise
     */
    public function installWpCli(): bool
    {
        // Ensure SSH connection is established
        $this->verifyConnectionSsh();

        // Define paths
        $tmpPath     = '/tmp/wp-cli.phar';
        $installPath = '/usr/local/bin/wp';

        // Check if WP-CLI is already installed
        $checkCommand = "wp --info 2>/dev/null | grep -q 'WP-CLI version' && echo 'exists'";
        $wpCliExists  = Helper\trim_if_string($this->execSsh($checkCommand));

        if ($wpCliExists === 'exists') {
            $this->logger->info('WP-CLI is already installed');

            return true;
        }

        // Download WP-CLI to temporary location
        $this->logger->info('Downloading WP-CLI...');
        if (!$this->executeCommand("curl -o $tmpPath https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar")) {
            $this->logger->error('Failed to download WP-CLI');

            return false;
        }

        // Make the file executable
        $this->logger->info('Making WP-CLI executable...');
        if (!$this->executeCommand("chmod +x $tmpPath")) {
            $this->logger->error('Failed to make WP-CLI executable');

            return false;
        }

        // Move to /usr/local/bin
        $this->logger->info('Moving WP-CLI to system directory...');
        if (!$this->executeCommand("mv $tmpPath $installPath")) {
            $this->logger->error('Failed to move WP-CLI to system directory');

            return false;
        }

        // Verify installation
        $this->logger->info('Verifying WP-CLI installation...');
        if (!$this->executeCommand('wp --info')) {
            $this->logger->error('WP-CLI installation verification failed');

            return false;
        }

        $this->logger->info('WP-CLI installed successfully');

        return true;
    }

    /**
     * Configures a droplet with recommended settings and installations.
     *
     * This method orchestrates the execution of various configuration methods to set up
     * a droplet with optimal settings for web hosting. It includes:
     * - Basic system configurations (aliases, screen, nano)
     * - PHP installations and configurations
     * - MySQL configurations
     * - CyberPanel updates and configurations
     * - Additional tools installation (WP-CLI)
     *
     * @param bool $updateCyberPanel Whether to update CyberPanel
     * @param bool $updateOs         Whether to update OS packages during CyberPanel update
     * @param bool $pipInstall       Whether to also pip install
     * @param bool $updateApt        Whether to update apt packages
     * @param bool $phpDisplayErrors Whether to enable PHP display errors
     * @param int  $mysqlPort        MySQL port to open in firewall
     * @param int  $timeout          SSH timeout in seconds
     *
     * @throws \Exception If SSH connection fails or if critical configurations fail
     *
     * @return bool Returns true if all configurations were successful, false if any failed
     */
    public function configureDroplet(
        bool $updateCyberPanel = true,
        bool $updateOs = true,
        bool $pipInstall = true,
        bool $updateApt = true,
        bool $phpDisplayErrors = false,
        int $mysqlPort = 3306,
        int $timeout = 3600
    ): bool {
        try {
            $this->logger->info('Starting configureDroplet()...');

            // Basic System Configurations
            $this->logger->info('Configuring basic system utilities...');

            if (!$this->setupAliasesAndFunctions()) {
                $this->logger->error('Failed to set up aliases and functions');

                return false;
            }

            if (!$this->configureScreen()) {
                $this->logger->error('Failed to configure screen utility');

                return false;
            }

            if (!$this->updateNanoCtrlFSearchBinding()) {
                $this->logger->error('Failed to update nano search binding');

                return false;
            }

            // CyberPanel Configuration
            $this->logger->info('Configuring CyberPanel...');

            if ($updateCyberPanel && !$this->updateCyberPanel($updateOs, $pipInstall, $timeout)) {
                $this->logger->error('Failed to update CyberPanel');

                return false;
            }

            if (!$this->enableCyberPanelApiAccess()) {
                $this->logger->error('Failed to enable CyberPanel API access');

                return false;
            }

            if (!$this->updateVhostPy()) {
                $this->logger->error('Failed to update vhost.py');

                return false;
            }

            if (!$this->updateVhostConfsPy()) {
                $this->logger->error('Failed to update vhostConfs.py');

                return false;
            }

            // PHP Installation and Configuration
            $this->logger->info('Installing and configuring PHP...');

            if (!$this->installPhpVersionsAndExtensions($updateApt, $timeout)) {
                $this->logger->error('Failed to install PHP versions and extensions');

                return false;
            }

            if (!$this->installLiteSpeedPhpVersionsAndExtensions($updateApt, $timeout)) {
                $this->logger->error('Failed to install LiteSpeed PHP versions');

                return false;
            }

            if (!$this->configurePhp($phpDisplayErrors)) {
                $this->logger->error('Failed to configure PHP');

                return false;
            }

            // MySQL Configuration
            $this->logger->info('Configuring MySQL...');

            if (!$this->configureMySql()) {
                $this->logger->error('Failed to configure MySQL');

                return false;
            }

            if (!$this->updateMyCnfPassword()) {
                $this->logger->error('Failed to update MySQL configuration password');

                return false;
            }

            if (!$this->openFirewall($mysqlPort)) {
                $this->logger->error('Failed to open MySQL port in firewall');

                return false;
            }

            // Additional Tools
            $this->logger->info('Installing additional tools...');

            if (!$this->installWpCli()) {
                $this->logger->error('Failed to install WP-CLI');

                return false;
            }

            $this->logger->info('Droplet configuration completed successfully');

            return true;
        } catch (\Exception $e) {
            $this->logger->error('Error during droplet configuration: ' . $e->getMessage());

            throw $e;
        }
    }
}
