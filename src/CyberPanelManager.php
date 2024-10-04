<?php

namespace FOfX\DropletManager;

/**
 * CyberPanelManager class
 *
 * This class is responsible for managing CyberPanel operations such as creating
 * and deleting websites, using the configuration provided by the ConfigurationManager.
 */
class CyberPanelManager
{
    private $config;

    /**
     * Constructor: Retrieve the configuration for CyberPanel.
     *
     * @param ConfigurationManager $configManager the configuration manager instance
     */
    public function __construct(ConfigurationManager $configManager)
    {
        // Retrieve the config array from the ConfigurationManager
        $this->config = $configManager->getConfig();
    }

    /**
     * Creates a new website in CyberPanel.
     *
     * @param string $domain   the domain name for the new website
     * @param string $email    the email associated with the website
     * @param string $user     the user who will own the website
     * @param string $password the password for the user
     *
     * @return void
     */
    public function createWebsite($domain, $email, $user, $password)
    {
        // Use the $this->config array here for CyberPanel settings
        // For example, $this->config['cyberpanel']['server_ip'] or other settings
        $serverIp = $this->config['cyberpanel']['server_ip'];
    }

    /**
     * Deletes a website in CyberPanel.
     *
     * @param string $domain the domain name of the website to delete
     *
     * @return void
     */
    public function deleteWebsite($domain)
    {
        // Use the $this->config array here
    }
}
