<?php

/**
 * API Wrapper for Cyberpanel
 * by @jetchirag
 *
 * @link https://github.com/jetchirag/cyberpanel-whmcs
 */

namespace FOfX\DropletManager;

class CyberApi
{
    private $ip;
    private $port;

    /**
     * Constructor for CyberApi
     *
     * @param string $ip
     * @param int    $port
     */
    public function __construct(string $ip, int $port)
    {
        $this->ip   = $ip;
        $this->port = $port;
    }

    /**
     * Call the Cyberpanel API.
     *
     * Since the server host name might not be set up or have propagated yet, we can use the IP:Port instead.
     *
     * @param array  $params The parameters to pass to the API
     * @param string $url    The URL to call
     * @param bool   $useIP  Whether to use the IP:Port instead of serverhostname:serverport
     *
     * @return string
     */
    private function callUrl(array $params, string $url, bool $useIP = true): string
    {
        if ($useIP) {
            return 'https://' . $this->ip . ':' . $this->port . '/api/' . $url;
        } else {
            return (($params['serversecure']) ? 'https' : 'http') . '://' . $params['serverhostname'] . ':' . $params['serverport'] . '/api/' . $url;
        }
    }

    private function call_cyberpanel($params, $url, $post = [])
    {
        $call = curl_init();
        curl_setopt($call, CURLOPT_URL, $this->callUrl($params, $url));
        curl_setopt($call, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        curl_setopt($call, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($call, CURLOPT_POST, true);
        curl_setopt($call, CURLOPT_POSTFIELDS, json_encode($post));
        curl_setopt($call, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($call, CURLOPT_SSL_VERIFYPEER, false);

        // Fire api
        $result = curl_exec($call);
        $info   = curl_getinfo($call);
        curl_close($call);
        $result = json_decode($result, true);

        // Return data
        return $result;
    }

    public function create_new_account($params)
    {
        $url        = 'createWebsite';
        $postParams = [
                'adminUser'     => $params['adminUser'],
                'adminPass'     => $params['adminPass'],
                'domainName'    => $params['domainName'],
                'websiteOwner'  => $params['websiteOwner'],
                'ownerEmail'    => $params['ownerEmail'],
                'ownerPassword' => $params['ownerPassword'],
                'packageName'   => $params['packageName'],
                'acl'           => 'user',
            ];

        $result = $this->call_cyberpanel($params, $url, $postParams);

        return $result;
    }

    public function change_account_status($params)
    {
        $url        = 'submitWebsiteStatus';
        $postParams = [
                'adminUser'   => $params['adminUser'],
                'adminPass'   => $params['adminPass'],
                'websiteName' => $params['websiteName'],
                'state'       => $params['state'],
            ];
        $result = $this->call_cyberpanel($params, $url, $postParams);

        return $result;
    }

    // Test connection
    public function verify_connection($params)
    {
        $url        = 'verifyConn';
        $postParams = [
                'adminUser' => $params['adminUser'],
                'adminPass' => $params['adminPass'],
            ];
        $result = $this->call_cyberpanel($params, $url, $postParams);

        return $result;
    }

    public function terminate_account($params)
    {
        $url        = 'deleteWebsite';
        $postParams = [
                'adminUser'  => $params['adminUser'],
                'adminPass'  => $params['adminPass'],
                'domainName' => $params['domainName'],
            ];
        $result = $this->call_cyberpanel($params, $url, $postParams);

        return $result;
    }

    public function change_account_password($params)
    {
        $url        = 'changeUserPassAPI';
        $postParams = [
                'adminUser'     => $params['adminUser'],
                'adminPass'     => $params['adminPass'],
                'websiteOwner'  => $params['websiteOwner'],
                'ownerPassword' => $params['ownerPassword'],
            ];
        $result = $this->call_cyberpanel($params, $url, $postParams);

        return $result;
    }

    public function change_account_package($params)
    {
        $url        = 'changePackageAPI';
        $postParams = [
                'adminUser'   => $params['adminUser'],
                'adminPass'   => $params['adminPass'],
                'websiteName' => $params['websiteName'],
                'packageName' => $params['packageName'],
            ];
        $result = $this->call_cyberpanel($params, $url, $postParams);

        return $result;
    }
}
