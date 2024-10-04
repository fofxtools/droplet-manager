<?php

namespace FOfX\DropletManager;

/**
 * ConfigurationManager class
 *
 * This class is responsible for loading and providing access to the configuration
 * for managing DigitalOcean droplets, CyberPanel accounts, and DNS settings.
 */
class ConfigurationManager
{
    private $config;

    /**
     * Constructor: Load the configuration from the config file.
     *
     * This method loads the configuration file and stores it in the `$config` property.
     *
     * @throws \Exception if the configuration file cannot be found or loaded
     */
    public function __construct()
    {
        // Resolve the path to the configuration file and load it
        $configFilePath = resolve_config_file_path('config' . DIRECTORY_SEPARATOR . 'droplet-manager.config.php');
        if (!$configFilePath) {
            throw new \Exception('Configuration file not found!');
        }

        $this->config = load_config($configFilePath);
    }

    /**
     * Get the entire configuration array.
     *
     * @return array the configuration data loaded from the file
     */
    public function getConfig(): array
    {
        return $this->config;
    }

    /**
     * Get a specific configuration value by key.
     *
     * @param string $key the configuration key to retrieve the value for
     *
     * @return mixed|null the configuration value or null if the key is not found
     */
    public function get(string $key)
    {
        return $this->config[$key] ?? null;
    }
}
