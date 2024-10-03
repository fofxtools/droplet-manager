<?php

namespace FOfX\DropletManager;

class DropletManager
{
    private $config;

    public function __construct(ConfigurationManager $configManager)
    {
        // Retrieve the config array from the ConfigurationManager
        $this->config = $configManager->getConfig();
    }

    public function createDroplet($name, $region, $size)
    {
        // Example usage of $this->config for DigitalOcean settings
        $apiToken = $this->config['digitalocean']['token'];
        $imageId  = $this->config['digitalocean']['image_id'];
        // Proceed with creating the droplet using these config values
    }

    public function deleteDroplet($dropletId)
    {
        // Use the $this->config array here, if needed for API requests
    }
}
