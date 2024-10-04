<?php

namespace FOfX\DropletManager;

/**
 * DropletManager class
 *
 * This class is responsible for managing DigitalOcean droplets, including creating
 * and deleting droplets, using configurations provided by the ConfigurationManager.
 */
class DropletManager
{
    private $config;

    /**
     * Constructor: Retrieve the configuration for DigitalOcean droplet management.
     *
     * @param ConfigurationManager $configManager the configuration manager instance
     */
    public function __construct(ConfigurationManager $configManager)
    {
        // Retrieve the config array from the ConfigurationManager
        $this->config = $configManager->getConfig();
    }

    /**
     * Creates a new droplet in DigitalOcean.
     *
     * @param string $name   the name of the droplet
     * @param string $region the region to create the droplet in
     * @param string $size   the size of the droplet
     *
     * @return void
     */
    public function createDroplet($name, $region, $size)
    {
        // Example usage of $this->config for DigitalOcean settings
        $apiToken = $this->config['digitalocean']['token'];
        $imageId  = $this->config['digitalocean']['image_id'];
        // Proceed with creating the droplet using these config values
    }

    /**
     * Deletes a droplet in DigitalOcean.
     *
     * @param int $dropletId the ID of the droplet to delete
     *
     * @return void
     */
    public function deleteDroplet($dropletId)
    {
        // Use the $this->config array here, if needed for API requests
    }
}
