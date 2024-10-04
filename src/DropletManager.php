<?php

namespace FOfX\DropletManager;

use phpseclib3\Net\SSH2;

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

    /**
     * Constructor: Retrieve the configuration for DigitalOcean droplet management.
     *
     * @param string|array|null $config      The path to the configuration file or a config array for testing
     * @param ?string           $dropletName The name of the droplet to manage
     */
    public function __construct(string|array|null $config = 'config' . DIRECTORY_SEPARATOR . 'droplet-manager.config.php', ?string $dropletName = null)
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
    }

    /**
     * Set the name of the droplet to manage.
     *
     * @param string $dropletName The name of the droplet to manage
     */
    public function setDropletName(string $dropletName)
    {
        $this->dropletName = $dropletName;
    }

    /**
     * Get the name of the droplet being managed.
     *
     * @return string The name of the droplet being managed
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
     * @throws \Exception if the droplet configuration is missing or if SSH login fails
     *
     * @return bool returns true if the SSH connection is successfully established
     */
    public function verifyConnectionSsh()
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
     * @throws \Exception if the droplet configuration is missing or if the API connection fails
     *
     * @return bool returns true if the API connection is successfully verified, false otherwise
     */
    public function verifyConnectionCyberApi()
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
}
