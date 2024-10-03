<?php

namespace FOfX\DropletManager;

class CyberPanelManager
{
    private $config;

    public function __construct(ConfigurationManager $configManager)
    {
        // Retrieve the config array from the ConfigurationManager
        $this->config = $configManager->getConfig();
    }

    public function createWebsite($domain, $email, $user, $password)
    {
        // Use the $this->config array here for CyberPanel settings
        // For example, $this->config['cyberpanel']['server_ip'] or other settings
        $serverIp = $this->config['cyberpanel']['server_ip'];
    }

    public function deleteWebsite($domain)
    {
        // Use the $this->config array here
    }
}
