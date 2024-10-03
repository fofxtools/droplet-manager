<?php

namespace FOfX\DropletManager;

/**
 * ConfigurationManager class
 *
 * This class is responsible for loading and providing access to the configuration.
 */
class ConfigurationManager
{
    private $config;

    /**
     * Constructor: Load the configuration from the config file.
     *
     * @throws \Exception if the configuration file cannot be found.
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
     * @return array The configuration data.
     */
    public function getConfig(): array
    {
        return $this->config;
    }

    /**
     * Get a specific configuration value by key.
     *
     * @param string $key The configuration key.
     *
     * @return mixed|null The configuration value or null if the key is not found.
     */
    public function get(string $key)
    {
        return $this->config[$key] ?? null;
    }
}
