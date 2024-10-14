<?php

namespace FOfX\DropletManager;

use phpseclib3\Net\SSH2;
use DigitalOceanV2\Client as DigitalOceanClient;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Monolog\Level;
use Namecheap\Api as NamecheapApi;
use Namecheap\Domain\DomainsDns;

/**
 * Manager class
 *
 * This class is responsible for managing DigitalOcean droplets, including creating
 * and deleting droplets.
 */
class Manager
{
    private $config;
    private $cyberApi;
    private $dropletName;
    private $sshConnection    = null;
    private $sshAuthenticated = false;
    private $digitalOceanClient;
    private $digitalOceanClientIsAuthenticated = false;
    private $cyberLinkConnection;
    private Logger $logger;
    private $namecheapApi;

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
                    'kernel'    => $dropletInfo->kernel ? $dropletInfo->kernel->id : null,
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
            float_sleep($sleepDuration);
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
        $command = sprintf('stat -c "%%U" /home/%s', escapeshellarg($domain));
        $output  = trim($this->sshConnection->exec($command));

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
     * @param string $domainName The domain name for which HTTPS redirection should be configured.
     *
     * @return bool True if the file was created and configured successfully, false on failure.
     */
    public function createHtaccessForHttpsRedirect(string $domainName): bool
    {
        // Ensure SSH connection is established
        $this->verifyConnectionSsh();

        // Define the .htaccess content for HTTPS redirection
        $htaccessContent = <<<EOF
RewriteEngine On
RewriteCond %{HTTPS}  !=on
RewriteRule ^/?(.*) https://%{SERVER_NAME}/\$1 [R,L]
EOF;

        // Securely add the .htaccess content to the file on the server
        $escapedDomain = escapeshellarg($domainName);
        $command       = sprintf(
            'cat <<EOF > /home/%s/public_html/.htaccess
%s
EOF',
            $escapedDomain,
            $htaccessContent
        );
        $this->sshConnection->exec($command);

        // Retrieve the Linux user for the domain
        $username = $this->getLinuxUserForDomain($domainName);

        // Check if user retrieval was successful
        if ($username === false) {
            $this->logger->error("Did not attempt to set ownership for .htaccess due to missing Linux user for domain: {$domainName}");

            return false;
        }

        // Set the correct ownership for the .htaccess file to the domain owner
        $ownershipCommand = sprintf('chown %s:%s /home/%s/public_html/.htaccess', escapeshellarg($username), escapeshellarg($username), $escapedDomain);
        $this->sshConnection->exec($ownershipCommand);

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
        $dbName = sanitize_domain_for_database($domainName, $username);

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
        $dbName = sanitize_domain_for_database($domainName, $username);

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
        $database = sanitize_domain_for_database($domainName, $username);

        // Construct the command to grant remote access
        $grantCommand = sprintf(
            "mysql -uroot -p%s -e \"GRANT ALL PRIVILEGES ON %s.* TO '%s'@'%%' IDENTIFIED BY '%s'; FLUSH PRIVILEGES;\"",
            escapeshellarg($this->config[$this->dropletName]['mysql_root_password']),
            escapeshellarg($database),
            escapeshellarg($username),
            escapeshellarg($password)
        );

        // Execute the grant command via SSH
        try {
            $output = $this->sshConnection->exec($grantCommand);
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
            escapeshellarg($username),
            escapeshellarg($newPassword)
        );
        $output = $this->sshConnection->exec($changePasswordCommand);

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
            $verifyCommand = 'sudo passwd -S ' . escapeshellarg($username);
            $verifyOutput  = $this->sshConnection->exec($verifyCommand);

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
     * @return bool Returns true if the configuration update was successful, false if an error occurred.
     */
    public function enableSymlinksForDomain(string $domainName): bool
    {
        // Ensure SSH connection is established
        $this->verifyConnectionSsh();

        // Command to update the symbolic link restrictions for the domain
        // Use escapeshellcmd() instead of escapeshellarg() to avoid issue with quotes
        $command = sprintf(
            "sed -i '/^virtualHost %s {/,/^}/ s/restrained[[:space:]]*[0-9]/restrained              0/' /usr/local/lsws/conf/httpd_config.conf",
            escapeshellcmd($domainName)
        );

        // Execute the command on the server
        $output = $this->sshConnection->exec($command);

        if ($output === false) {
            $this->logger->error("Failed to enable symbolic links for domain: $domainName");

            return false;
        }

        $this->logger->info("Symbolic links enabled for domain: $domainName");

        return true;
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

        return $cyber->restartLiteSpeed();
    }

    /**
     * Updates the nameservers on Namecheap for a given domain.
     *
     * The IP of the server this script is running on, must be whitelisted for the Namecheap API.
     * To do this, go to Account>Profile>Tools>Business & Dev Tools>Namecheap API Access>Manage.
     * And edit the Whitelisted IPs.
     *
     * @param string            $domain       The domain name to update.
     * @param bool              $sandbox      Whether to use Namecheap's sandbox environment.
     * @param NamecheapApi|null $namecheapApi Optional injected NamecheapApi instance. For testing.
     * @param DomainsDns|null   $domainsDns   Optional injected DomainsDns instance. For testing.
     *
     * @return string|array|bool Returns the API response.
     */
    public function updateNameserversNamecheap(
        string $domain,
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

        $response = $domainsDns->setCustom($sld, $tld, 'ns1.digitalocean.com,ns2.digitalocean.com,ns3.digitalocean.com');

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
}
