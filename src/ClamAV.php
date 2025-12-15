<?php

namespace Symbiote\SteamedClams;

use LogicException;
use Psr\Log\LoggerInterface;
use SilverStripe\Assets\File;
use SilverStripe\Assets\Folder;
use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Model\List\ArrayList;
use SilverStripe\Model\List\SS_List;
use SilverStripe\ORM\DataList;
use SilverStripe\ORM\DataObject;
use Socket\Raw\Exception;
use Socket\Raw\Factory;
use Symbiote\SteamedClams\Model\ClamAVScan;
use Xenolope\Quahog\Client;

class ClamAV
{
    use Injectable;
    use Configurable;

    public const string MODULE_DIR = 'steamedclams';

    /**
     * If ClamAV daemon can't be connected to or is offline.
     */
    public const bool OFFLINE = false;

    protected ?Client $clamd_instance = null;

    protected ?\Exception $last_exception = null;

    protected ?bool $_cache_isOffline = null;

    /**
     * Configure this to ignore `File` records created before the date
     * provided.
     *
     * eg. You installed this module on a 5 year old website and to avoid a bulky
     *       amount of `ClamAVScan` records from `ClamAVInstallTask`, you're just opting
     *       to not scan those old files for viruses
     *
     * @var string
     */
    private static string $initial_scan_ignore_before_datetime = '1970-12-25 00:00:00';

    /**
     * If enabled, if ClamAV daemon isn't running or isn't installed
     * the file will be denied as if it has a virus.
     */
    private static bool $deny_on_failure = false;

    /**
     * Settings that must be identical to your clamd.conf file.
     *
     * @config
     *
     * @var array
     */
    private static array $clamd = [
        // Path to a local socket file the daemon will listen on.
        'LocalSocket' => '/var/run/clamav/clamd.ctl',
    ];

    public function scanFileRecordForVirus(File $file): ?ClamAVScan
    {
        $record = $this->scanFileForVirus($file);
        if ($record && $record instanceof DataObject) {
            $record->FileID = $file->ID;
        }

        return $record;
    }

    public function scanFileForVirus(File $file): ?ClamAVScan
    {
        $filepath = $file->getFullPath(true);

        try {
            $clamd = $this->getClamd();

            $scanResult = $clamd->scanStream($file->getString());
        } catch (Exception $e) {
            $this->setLastExceptionAndLog($e);
            $scanResult = null;
        }

        if (!$scanResult) {
            $record = ClamAVScan::create();
            $record->Filename = $filepath;
            $record->IPAddress = $this->getIP();
            $record->setRawData($scanResult);

            return $record;
        }

        $filename = $scanResult->getFilename();
        if ($filename === 'stream') {
            $filename = $filepath;
        }

        $record = ClamAVScan::create();
        $record->Filename = $filepath;
        $record->IPAddress = $this->getIP();
        $record->IsScanned = 1;
        $record->IsInfected = $scanResult->hasFailed();
        $record->setRawData((array)$scanResult);

        return $record;
    }

    public function endClamdSession(): void
    {
        $this->getClamd()->endSession();
    }

    /**
     * Get list of files that haven't been checked at all.
     * ie. before installation of module.
     */
    public function getInitialFileToScanList(): SS_List
    {
        $excludeFileIDs = ClamAVScan::get()->column('FileID');
        $excludeFileIDs = array_unique($excludeFileIDs);
        $list = $this->getBaseFileList();
        if (!$list) {
            return new ArrayList();
        }

        if (!empty($excludeFileIDs)) {
            $list = $list->filter([
                'ID:not' => $excludeFileIDs,
            ]);
        }
        $ignoreBeforeDatetime = Config::inst()->get(__CLASS__, 'initial_scan_ignore_before_datetime');
        if ($ignoreBeforeDatetime) {
            $list = $list->filter([
                'Created:GreaterThanOrEqual' => $ignoreBeforeDatetime,
            ]);
            // Debug::dump(SS_Datetime::now()); Debug::dump($ignoreBeforeDatetime); Debug::dump($list->count()); exit;
        }

        return $list;
    }

    public function getBaseFileList(): DataList
    {
        $list = File::get();

        return $list->filter([
            'ClassName:not' => Folder::class,
        ]);
    }

    /**
     * Get list of files that couldn't be scanned when uploaded
     * due to ClamAV daemon being down or not properly configured
     * ie. after installation of module.
     */
    public function getFailedToScanFileList(): SS_List
    {
        $scanList = ClamAVScan::get();
        $scanList = $scanList->filter([
            'IsScanned' => 0,
            'Action' => ClamAVScan::ACTION_NONE,
            'FileID:not' => 0,
        ]);
        $fileIDs = $scanList->column('FileID');
        $fileIDs = array_unique($fileIDs);
        if (!$fileIDs) {
            return new ArrayList();
        }
        $list = $this->getBaseFileList();
        if (!$list) {
            return new ArrayList();
        }

        return $list->filter([
            'ID' => $fileIDs,
        ]);
    }

    public function isOffline(): bool
    {
        if ($this->_cache_isOffline !== null) {
            return (bool)$this->_cache_isOffline;
        }
        $result = $this->version();
        $result = ($result === ClamAV::OFFLINE);

        $this->_cache_isOffline = $result;

        return (bool)$this->_cache_isOffline;
    }

    public function version(): bool|string
    {
        $this->last_exception = null;

        try {
            $clamd = $this->getClamd();

            $version = $clamd->version();
        } catch (Exception $e) {
            $this->setLastExceptionAndLog($e);
            $version = self::OFFLINE;
        }

        return $version;
    }

    /**
     * Get the last exception caught by this.
     * Allows you to report the exact error to an admin/developer user in the CMS.
     */
    public function getLastException(): \Exception
    {
        return $this->last_exception;
    }

    /**
     * Return underlying Clamd implementation.
     */
    protected function getClamd(bool $startSession = true): ?Client
    {
        if ($this->clamd_instance) {
            return $this->clamd_instance;
        }

        $clamdConf = Config::inst()->get(__CLASS__, 'clamd');
        $localSocket = isset($clamdConf['LocalSocket']) ? $clamdConf['LocalSocket'] : '';

        if (!$localSocket) {
            throw new LogicException('Empty value for "clamd.LocalSocket" config not allowed.');
        }

        try {
            $socket = (new Factory())->createClient('unix://' . $localSocket);
            $clamdClient = new Client($socket, 30, PHP_NORMAL_READ);

            if ($startSession) {
                $clamdClient->startSession();
            }
        } catch (Exception $e) {
            throw new Exception('ClamAV socket error: ' . $e->getMessage());
        }

        return $this->clamd_instance = $clamdClient;
    }

    /**
     * Set exception, if it has a non-falsey value, log it.
     */
    protected function setLastExceptionAndLog(\Exception $e): void
    {
        if ($e) {
            Injector::inst()->get(LoggerInterface::class)->warning('Query executed: ' . $e->getMessage());
        }
        $this->last_exception = $e;
    }

    /**
     * Get the current users IP address.
     */
    protected function getIP(): string
    {
        if (!Controller::curr()) {
            if (Director::is_cli()) {
                // If running from command line, you can assume it's
                // the local machine.
                return '127.0.0.1';
            }

            return '';
        }
        $request = Controller::curr()->getRequest();
        if (!$request) {
            return '';
        }

        return $request->getIP();
    }
}
