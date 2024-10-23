<?php

namespace FOfX\DropletManager;

use Exception;
use phpseclib3\Net\SSH2;
use phpseclib3\Crypt\PublicKeyLoader;
use League\Flysystem\Filesystem;
use League\Flysystem\PhpseclibV3\SftpAdapter;
use League\Flysystem\PhpseclibV3\SftpConnectionProvider;
use League\Flysystem\UnixVisibility\PortableVisibilityConverter;

/**
 * Class CyberLink
 * Description: Fills the missing CyberPanel API.
 * Warning: It's not an API or API service. It uses ssh and sftp protocols to get job done and requires root access to server.
 * Author: Burak BOZ <info@burakboz.net>
 * Github: https://github.com/burakboz
 */
class CyberLink
{
    #region Core
    public const
        phpVersion = '8.1',
        owner      = 'admin',
        package    = 'Default';
    private $ssh;
    private $fs;
    private $lastMessage = '';

    /**
     * CyberLink constructor.
     *
     * @param      $ip
     * @param      $user
     * @param      $password
     * @param null $key
     * @param int  $port
     * @param int  $timeout
     * @param bool $enableSecureFTP
     *
     * @throws Exception
     */
    public function __construct($ip, $user, $password, $key = null, $port = 22, $timeout = 300, $enableSecureFTP = false)
    {
        #region SSH2
        $this->ssh = new SSH2($ip, $port, $timeout);
        if (!is_null($key)) {
            $rsa = PublicKeyLoader::load(file_get_contents($key), $password);
        }
        if (!$this->ssh->login($user, (isset($rsa) ? $rsa : $password))) {
            throw new Exception('SSH Login Failed');
        }
        if (trim($this->ssh->exec('whoami')) != 'root') {
            throw new Exception('SSH user must be root');
        }
        #endregion

        #region Secure FTP File System
        if ($enableSecureFTP) {
            $connectionProvider = new SftpConnectionProvider(
                $ip,
                $user,
                $password,
                $key,
                null,
                $port,
                false,
                $timeout
            );

            $adapter = new SftpAdapter($connectionProvider, '/', PortableVisibilityConverter::fromArray([
                'file' => [
                    'public'  => 0644,
                    'private' => 0600,
                ],
                'dir' => [
                    'public'  => 0755,
                    'private' => 0700,
                ],
            ]));

            $this->fs = new Filesystem($adapter);
        }
        #endregion

        return true;
    }

    /**
     * @param       $operation
     * @param array $parameters
     *
     * @return string
     */
    private function commandBuilder($operation, array $parameters = [])
    {
        $command = ['cyberpanel', $operation];
        if (!empty($parameters)) {
            foreach ($parameters as $parameter => $value) {
                $command[] = '--' . $parameter;
                $command[] = escapeshellarg($value);
            }
        }

        return implode(' ', $command);
    }

    /**
     * Modified parse function to optionally handle multiple JSON objects in the output
     * and optionally return the parsed data.
     *
     * @param      $str
     * @param bool $endOfString     If true, the pattern will match the end of the string.
     *                              This is because createWebsite and issueSSL might return multiple JSON objects.
     *                              The last one contains the success message.
     * @param bool $returnParseData If true, the function will return the parsed data instead of a boolean.
     *
     * @return mixed
     */
    public function parse($str, bool $endOfString = false, $returnParseData = false)
    {
        if ($endOfString) {
            $pattern = '
/
\{              # { character
    (?:         # non-capturing group
        [^{}]   # anything that is not a { or }
        |       # OR
        (?R)    # recurses the entire pattern
    )*          # previous group zero or more times
\}              # } character
\s*             # optional whitespace
$               # end of string
/x
';
        } else {
            $pattern = '
/
\{              # { character
    (?:         # non-capturing group
        [^{}]   # anything that is not a { or }
        |       # OR
        (?R)    # recurses the entire pattern
    )*          # previous group zero or more times
\}              # } character
/x
';
        }

        preg_match($pattern, $str, $json);
        $parseData = json_decode($json[0]);

        if ($returnParseData) {
            return $parseData;
        }

        $this->lastMessage = trim(str_replace($json[0], '', $str));

        return $this->getBoolResult($parseData);
    }

    /**
     * @param $result
     *
     * @return bool
     */
    public function getBoolResult($result)
    {
        if (isset($result->errorMessage) and $result->errorMessage != 'None') {
            return false;
        }
        if (isset($result->error_message) and $result->error_message != 'None') {
            return false;
        }
        if (isset($result->success) and $result->success == 1) {
            return boolval($result->success);
        }
        if (isset($result->status) and $result->status == 1) {
            return boolval($result->status);
        }

        return false;
    }

    /**
     * @return string
     */
    public function getLastMessage()
    {
        return $this->lastMessage;
    }

    #region Extra Functions
    // I've added some extra salt
    /**
     * @param $i
     *
     * @return string
     */
    public function domain2user($i)
    {
        $i = trim($i);
        $t = ['/Ğ/', '/Ü/', '/Ş/', '/İ/', '/Ö/', '/Ç/', '/ğ/', '/ü/', '/ş/', '/ı/', '/ö/', '/ç/'];
        $r = ['g', 'u', 's', 'i', 'o', 'c', 'g', 'u', 's', 'i', 'o', 'c'];
        $i = preg_replace('/[^0-9a-zA-ZÜŞİÖÇğüşıöç]/', ' ', $i);
        $i = preg_replace($t, $r, $i);
        $i = preg_replace("/\s|\s+/", '', $i);
        $i = preg_replace('/^[0-9]+/', '', $i);
        $i = preg_replace('/-$/', '', $i);

        return substr(strtolower($i), 0, 5) . substr(md5(microtime(true)), 0, 5);
    }

    /**
     * @param $password
     *
     * @return string
     */
    public function resetAdminPassword($password)
    {
        return trim($this->ssh->exec('python /usr/local/CyberCP/plogical/adminPass.py --password ' . escapeshellarg($password)));
    }

    /**
     * @return string
     */
    public function upgradeCyberPanel()
    {
        $upgrade = <<<EOL
cd
rm -f /root/upgrade.py
wget -O /root/upgrade.py http://cyberpanel.net/upgrade.py
python /root/upgrade.py
EOL;
        foreach (explode(PHP_EOL, $upgrade) as $command) {
            $response = $this->ssh->exec(trim($command));
        }

        return trim($response);
    }

    /**
     * @return string
     */
    public function restartLiteSpeed()
    {
        return trim($this->ssh->exec('/usr/local/lsws/bin/lswsctrl restart'));
    }

    /**
     * @return string
     */
    public function rebootServer()
    {
        return trim($this->ssh->exec('reboot'));
    }

    /**
     * @return string
     */
    public function uptime()
    {
        return trim($this->ssh->exec('uptime'));
    }

    #region Danger Zone
    /**
     * Warning! This method shouldn't be trusted. In future versions of CyberPanel and LiteSpeed may cause system failure. Use at your own risk.
     *
     * @param $domain
     * @param $publicKey
     * @param $privateKey
     *
     * @throws Exception
     *
     * @return bool
     */
    public function setCustomSSL($domain, $publicKey, $privateKey)
    {
        if (is_null($this->fs)) {
            throw new Exception('This method requires SFTP feature.');
        }
        $sslPath        = '/etc/letsencrypt/live/' . $domain;
        $privateKeyFile = $sslPath . '/privkeyCustom.pem';
        $publicKeyFile  = $sslPath . '/fullchainCustom.pem';
        if (!$this->fs->directoryExists($sslPath)) {
            $this->fs->createDirectory($sslPath);
        }
        if ($this->fs->write($publicKeyFile, trim($publicKey)) && $this->fs->write($privateKeyFile, trim($privateKey))) {
            $this->ssh->exec('chown -R lsadm:lsadm ' . escapeshellarg($sslPath));
            $this->ssh->exec('chmod 644 ' . escapeshellarg($publicKeyFile));
            $this->ssh->exec('chmod 644 ' . escapeshellarg($privateKeyFile));

            return $this->enableCustomSSL($domain);
        }

        return false;
    }

    /**
     * @param $domain
     *
     * @throws Exception
     *
     * @return bool
     */
    private function enableCustomSSL($domain)
    {
        $vhost = "/usr/local/lsws/conf/vhosts/{$domain}/vhost.conf";

        try {
            $contents = $this->fs->read($vhost);
            if (preg_match("/(vhssl(\s+|){.*?})/si", $contents, $matchSSL)) {
                $contents = str_replace($matchSSL[0], '', $contents);
            }
            unset($matchSSL);
            $sslConf = <<<EOL


vhssl  {
  keyFile                 /etc/letsencrypt/live/{$domain}/privkeyCustom.pem
  certFile                /etc/letsencrypt/live/{$domain}/fullchainCustom.pem
  certChain               1
  sslProtocol             30
}

EOL;
            $contents = trim(preg_replace("/\n\n+/", "\n\n", $contents . $sslConf));
            if ($this->fs->write($vhost, $contents)) {
                #region httpd_config.conf
                $httpd_config = '/usr/local/lsws/conf/httpd_config.conf';
                $contents     = '';
                $contents     = $this->fs->read($httpd_config);
                $mapPrepend   = "\n  map                     $domain $domain\n";
                if (preg_match("/(listener(\s+|)SSL(\s+|){.*?})/si", $contents, $matchListener)) {
                    if (stristr($matchListener[0], "$domain $domain") !== false) {
                        $this->restartLiteSpeed();

                        return true;
                    } else {
                        $contents = preg_replace("/(listener(\s+|)SSL(\s+|){)/si", "$1{$mapPrepend}", $contents);
                        if ($this->fs->write($httpd_config, $contents)) {
                            $this->restartLiteSpeed();

                            return true;
                        }
                    }
                } else {
                    throw new Exception("SSL Listener doesn't exist.", 404);
                }
                #endregion
            }
        } catch (Exception $e) {
            throw new Exception("Virtual Host Doesn't Exist.", 404);
        }

        return false;
    }
    #endregion

    #endregion

    #endregion

    #region CLI Functions
    #region Website Functions
    /**
     * @param        $domainName
     * @param        $email
     * @param string $owner
     * @param string $package
     * @param string $phpVersion
     *
     * @throws Exception
     *
     * @return bool
     */
    public function createWebsite(
        $domainName,
        $email,
        $owner = self::owner,
        $package = self::package,
        $phpVersion = self::phpVersion,
        $debug = false
    ) {
        if (empty($domainName)) {
            throw new Exception('Domain name cannot be empty!');
        }
        if (empty($email)) {
            throw new Exception('Email cannot be empty!');
        }

        $command = $this->commandBuilder(__FUNCTION__, [
            'package'     => $package,
            'owner'       => $owner,
            'domainName'  => $domainName,
            'email'       => $email,
            'php'         => $phpVersion,
            'ssl'         => 1,
            'dkim'        => 1,
            'openBasedir' => 1,
        ]);
        $output = $this->ssh->exec($command);

        if ($debug) {
            var_dump($output);
        }

        // Use end_of_string = true because there may be multiple JSON objects in the output
        return $this->parse($output, true);
    }

    /**
     * @param string $domainName
     * @param bool   $debug
     *
     * @throws Exception
     *
     * @return bool
     */
    public function deleteWebsite(string $domainName, bool $debug = false)
    {
        if (empty($domainName)) {
            throw new Exception('Domain name cannot be empty!');
        }

        $command = $this->commandBuilder(__FUNCTION__, [
            'domainName' => $domainName,
        ]);
        $output = $this->ssh->exec($command);

        if ($debug) {
            var_dump($output);
        }

        return $this->parse($output);
    }

    /**
     * @param        $masterDomain
     * @param        $childDomain
     * @param string $owner
     * @param string $phpVersion
     *
     * @throws Exception
     *
     * @return bool
     */
    public function createChild($masterDomain, $childDomain, $owner = self::owner, $phpVersion = self::phpVersion)
    {
        if (empty($masterDomain)) {
            throw new Exception('Master domain name cannot be empty!');
        }
        if (empty($childDomain)) {
            throw new Exception('Child domain name cannot be empty!');
        }

        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            'masterDomain' => $masterDomain,
            'childDomain'  => $childDomain,
            'owner'        => $owner,
            'php'          => $phpVersion,
        ])));
    }

    /**
     * @param $childDomain
     *
     * @throws Exception
     *
     * @return bool
     */
    public function deleteChild($childDomain)
    {
        if (empty($childDomain)) {
            throw new Exception('Child domain name cannot be empty!');
        }

        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            'childDomain' => $childDomain,
        ])));
    }

    /**
     * @return mixed
     */
    public function listWebsites(bool $namesOnly = false)
    {
        $command  = $this->commandBuilder(__FUNCTION__ . 'Json');
        $websites = json_decode($this->ssh->exec($command));

        if (!is_array($websites)) {
            // If the JSON output is not an array, decode again to get the correct format
            // Decode associative true to get array elements rather than objects
            $websites = json_decode($websites, true);
        }

        if ($namesOnly) {
            $names = [];
            foreach ($websites as $website) {
                $names[] = $website['domain'];
            }

            return $names;
        }

        return $websites;
    }

    /**
     * @param        $domainName
     * @param string $phpVersion
     *
     * @throws Exception
     *
     * @return bool
     */
    public function changePHP($domainName, $phpVersion = self::phpVersion)
    {
        if (empty($domainName)) {
            throw new Exception('Domain name cannot be empty!');
        }

        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            'domainName' => $domainName,
            'phpVersion' => $phpVersion,
        ])));
    }

    /**
     * @param        $domainName
     * @param string $packageName
     *
     * @throws Exception
     *
     * @return bool
     */
    public function changePackage($domainName, $packageName = self::package)
    {
        if (empty($domainName)) {
            throw new Exception('Domain name cannot be empty!');
        }

        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            'domainName'  => $domainName,
            'packageName' => $packageName,
        ])));
    }
    #endregion

    #region DNS Functions
    // TODO: implement dns functions
    #endregion

    #region Backup Functions
    /**
     * @param $domainName
     *
     * @throws Exception
     *
     * @return bool
     */
    public function createBackup($domainName)
    {
        if (empty($domainName)) {
            throw new Exception('Domain name cannot be empty!');
        }

        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            'domainName' => $domainName,
        ])));
    }

    /**
     * @param $domainName
     * @param $fileName
     *
     * @throws Exception
     *
     * @return bool
     */
    public function restoreBackup($domainName, $fileName)
    {
        if (empty($domainName)) {
            throw new Exception('Domain name cannot be empty!');
        }
        if (empty($fileName)) {
            throw new Exception('File name cannot be empty!');
        }

        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            'domainName' => $domainName,
            'fileName'   => $fileName,
        ])));
    }
    #endregion

    #region Package Functions
    /**
     * @param        $packageName
     * @param int    $diskSpace
     * @param int    $bandwidth
     * @param int    $emailAccounts
     * @param int    $dataBases
     * @param int    $ftpAccounts
     * @param int    $allowedDomains
     * @param string $owner
     *
     * @throws Exception
     *
     * @return bool
     */
    public function createPackage($packageName, $diskSpace = 1000, $bandwidth = 10000, $emailAccounts = 100, $dataBases = 100, $ftpAccounts = 100, $allowedDomains = 100, $owner = self::owner)
    {
        if (empty($packageName)) {
            throw new Exception('Package name cannot be empty!');
        }

        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            'packageName'    => $packageName,
            'diskSpace'      => $diskSpace,
            'bandwidth'      => $bandwidth,
            'emailAccounts'  => $emailAccounts,
            'dataBases'      => $dataBases,
            'ftpAccounts'    => $ftpAccounts,
            'allowedDomains' => $allowedDomains,
            'owner'          => $owner,
        ])));
    }

    /**
     * @param $packageName
     *
     * @throws Exception
     *
     * @return bool
     */
    public function deletePackage($packageName)
    {
        if (empty($packageName)) {
            throw new Exception('Package name cannot be empty!');
        }

        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            'packageName' => $packageName,
        ])));
    }

    /**
     * @return mixed
     */
    public function listPackages()
    {
        return json_decode($this->ssh->exec($this->commandBuilder(__FUNCTION__ . 'Json')));
    }
    #endregion

    #region Database Functions
    /**
     * @param $databaseWebsite
     * @param $dbName
     * @param $dbUsername
     * @param $dbPassword
     *
     * @throws Exception
     *
     * @return bool
     */
    public function createDatabase($databaseWebsite, $dbName, $dbUsername, $dbPassword)
    {
        if (empty($databaseWebsite)) {
            throw new Exception('Domain name cannot be empty!');
        }
        if (empty($dbName)) {
            throw new Exception('Database name cannot be empty!');
        }
        if (empty($dbUsername)) {
            throw new Exception('Database username cannot be empty!');
        }
        if (empty($dbPassword)) {
            throw new Exception('Database password cannot be empty!');
        };

        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            'databaseWebsite' => $databaseWebsite,
            'dbName'          => $dbName,
            'dbUsername'      => $dbUsername,
            'dbPassword'      => $dbPassword,
        ])));
    }

    /**
     * @param $dbName
     *
     * @throws Exception
     *
     * @return bool
     */
    public function deleteDatabase($dbName)
    {
        if (empty($dbName)) {
            throw new Exception('Database name cannot be empty!');
        }

        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            'dbName' => $dbName,
        ])));
    }

    /**
     * @param $databaseWebsite
     *
     * @return mixed
     */
    public function listDatabases($databaseWebsite, $namesOnly = false)
    {
        $command = $this->commandBuilder(__FUNCTION__ . 'Json', ['databaseWebsite' => $databaseWebsite]);
        $output  = $this->ssh->exec($command);
        // Must decode twice to get the correct format
        $json = json_decode(json_decode($output));

        if ($namesOnly && is_array($json)) {
            $names = [];
            foreach ($json as $database) {
                $names[$database->id] = $database->dbName;
            }

            return $names;
        }

        // If the JSON output is not an array, return an empty array
        if (!is_array($json)) {
            return [];
        }

        return $json;
    }
    #endregion

    #region Email Functions
    // TODO: implement email functions
    #endregion

    #region FTP Functions
    /**
     * @param        $domainName
     * @param        $userName
     * @param        $password
     * @param string $owner
     *
     * @throws Exception
     *
     * @return bool
     */
    public function createFTPAccount($domainName, $userName, $password, $owner = self::owner)
    {
        if (empty($domainName)) {
            throw new Exception('Domain name cannot be empty!');
        }
        if (empty($userName)) {
            throw new Exception('Username cannot be empty!');
        }
        if (empty($password)) {
            throw new Exception('Password cannot be empty!');
        }

        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            'domainName' => $domainName,
            'userName'   => $userName,
            'password'   => $password,
            'owner'      => $owner,
        ])));
    }

    /**
     * @param $userName
     *
     * @throws Exception
     *
     * @return bool
     */
    public function deleteFTPAccount($userName)
    {
        if (empty($userName)) {
            throw new Exception('Username cannot be empty!');
        }

        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            'userName' => $userName,
        ])));
    }

    /**
     * @param $userName
     * @param $password
     *
     * @throws Exception
     *
     * @return bool
     */
    public function changeFTPPassword($userName, $password)
    {
        if (empty($userName)) {
            throw new Exception('Username cannot be empty!');
        }
        if (empty($password)) {
            throw new Exception('Password cannot be empty!');
        }

        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            'userName' => $userName,
            'password' => $password,
        ])));
    }

    /**
     * @param $domainName
     *
     * @return mixed
     */
    public function listFTP($domainName)
    {
        return json_decode($this->ssh->exec($this->commandBuilder(__FUNCTION__ . 'Json', ['domainName' => $domainName])));
    }
    #endregion

    #region SSL Functions
    /**
     * @param string $domainName
     * @param bool   $debug
     *
     * @throws Exception
     *
     * @return bool
     */
    public function issueSSL($domainName, bool $debug = false)
    {
        if (empty($domainName)) {
            throw new Exception('Domain name cannot be empty!');
        }

        $command = $this->commandBuilder(__FUNCTION__, [
            'domainName' => $domainName,
        ]);
        $output = $this->ssh->exec($command);

        if ($debug) {
            var_dump($output);
        }

        // Use end_of_string = true because there may be multiple JSON objects in the output
        return $this->parse($output, true);
    }

    /**
     * @param $domainName
     *
     * @throws Exception
     *
     * @return bool
     */
    public function hostNameSSL($domainName)
    {
        if (empty($domainName)) {
            throw new Exception('Domain name cannot be empty!');
        }

        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            'domainName' => $domainName,
        ])));
    }

    /**
     * @param $domainName
     *
     * @throws Exception
     *
     * @return bool
     */
    public function mailServerSSL($domainName)
    {
        if (empty($domainName)) {
            throw new Exception('Domain name cannot be empty!');
        }

        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            'domainName' => $domainName,
        ])));
    }
    #endregion
    #endregion

    public function createUser($firstName, $lastName, $email, $username, $password, $websitesLimit = 0, $debug = false)
    {
        if (empty($firstName)) {
            throw new Exception('First name cannot be empty!');
        }
        if (empty($lastName)) {
            throw new Exception('Last name cannot be empty!');
        }
        if (empty($email)) {
            throw new Exception('Email cannot be empty!');
        }
        if (empty($username)) {
            throw new Exception('Username cannot be empty!');
        }
        if (empty($password)) {
            throw new Exception('Password cannot be empty!');
        }

        $command = $this->commandBuilder(__FUNCTION__, [
            'firstName'     => $firstName,
            'lastName'      => $lastName,
            'email'         => $email,
            'userName'      => $username,
            'password'      => $password,
            'websitesLimit' => $websitesLimit,
            'selectedACL'   => 'user',
            'securityLevel' => 'HIGH',
        ]);
        $output = $this->ssh->exec($command);

        if ($debug) {
            var_dump($output);
        }

        return $this->parse($output);
    }

    public function deleteUser($userName)
    {
        if (empty($userName)) {
            throw new Exception('Username cannot be empty!');
        }

        return $this->parse($this->ssh->exec($this->commandBuilder(__FUNCTION__, [
            'userName' => $userName,
        ])));
    }

    public function listUsers(bool $namesOnly = false)
    {
        $output    = $this->ssh->exec($this->commandBuilder(__FUNCTION__));
        $parseData = $this->parse($output, false, true);

        if (is_object($parseData) && isset($parseData->data)) {
            $users = json_decode($parseData->data, true);
            if ($namesOnly) {
                $names = [];
                foreach ($users as $user) {
                    $names[$user['id']] = $user['name'];
                }

                return $names;
            }

            return $users;
        }

        return [];
    }
}
