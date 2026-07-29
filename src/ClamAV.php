<?php

namespace Symbiote\SteamedClams;

use LogicException;
use Psr\Log\LoggerInterface;
use SilverStripe\Assets\FilenameParsing\ParsedFileID;
use SilverStripe\Assets\File;
use SilverStripe\Assets\Flysystem\FlysystemAssetStore;
use SilverStripe\Assets\Flysystem\LocalFilesystemAdapter;
use SilverStripe\Assets\Folder;
use SilverStripe\Assets\Storage\AssetStore;
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
use Xenolope\Quahog\Exception\ConnectionException;
use Xenolope\Quahog\Result;

class ClamAV
{
    use Injectable;
    use Configurable;

    public const string MODULE_DIR = 'steamedclams';

    /**
     * If ClamAV daemon can't be connected to or is offline.
     */
    public const bool OFFLINE = false;

    /**
     * clamd result statuses. Mirrors the (private) statuses in Xenolope\Quahog\Result
     */
    public const string STATUS_OK = 'OK';
    public const string STATUS_FOUND = 'FOUND';
    public const string STATUS_ERROR = 'ERROR';

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
     * How files are handed to the ClamAV daemon.
     *
     * false (default): the daemon reads the file directly from disk via the SCAN command.
     * true: the file is streamed to the daemon in chunks (INSTREAM). Required
     *   when the daemon cannot read the file off disk (e.g. remote/cloud or
     *   encrypted-at-rest stores). Subject to clamd's `StreamMaxLength`.
     *
     * When false but a local on-disk path can't be resolved (e.g. a cloud
     * asset store), the module automatically falls back to streaming.
     */
    private static bool $use_streams = false;

    /**
     * Chunk size (bytes) used when streaming a file to the daemon. A larger
     * value than the Quahog default (1KB) means far fewer socket writes for
     * large files.
     */
    private static int $stream_chunk_size = 8192;

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
            $scanResult = $this->getClamdScan($file);
        } catch (Exception|ConnectionException $e) {
            $this->setLastExceptionAndLog($e);
            $scanResult = null;
        }

        $record = ClamAVScan::create();
        $record->Filename = $filepath;
        $record->IPAddress = $this->getIP();

        // Daemon unreachable/offline: leave the record unscanned so it is retried
        // later (via the scan task / queued job) rather than silently trusted.
        if (!$scanResult) {
            $record->setRawData($scanResult);

            return $record;
        }

        // A scan *error* (e.g. clamd reached its size limit) is neither a clean
        // result nor an infection. Record it as unscanned so it is retried, and
        // never block the upload as if the file were a virus.
        if ($scanResult->isError()) {
            $this->setLastExceptionAndLog(new \RuntimeException(sprintf(
                'ClamAV could not scan "%s": %s',
                $filepath,
                (string)$scanResult->getReason()
            )));
        }

        $record->IsScanned = $scanResult->isError() ? 0 : 1;
        $record->IsInfected = $scanResult->isFound();
        $record->setRawData($this->normaliseScanResult($scanResult));

        return $record;
    }

    /**
     * Send a file to the ClamAV daemon and return its raw scan result.
     *
     * Returns null only when the daemon connection itself failed; a completed
     * scan (clean, infected or errored) always returns a {@link Result}.
     */
    protected function getClamdScan(File $file): ?Result
    {
        $clamd = $this->getClamd();

        // Preferred path: let the daemon read the file straight off disk.
        if (!self::config()->get('use_streams')) {
            $localPath = $this->getLocalFilesystemPath($file);
            if ($localPath !== null) {
                return $clamd->scanFile($localPath);
            }
        }

        // Fallback / opt-in: stream the file to the daemon in chunks straight from a read handle.
        $stream = $file->getStream();
        if (!is_resource($stream)) {
            return null;
        }

        try {
            return $clamd->scanResourceStream($stream, (int)self::config()->get('stream_chunk_size'));
        } finally {
            if (is_resource($stream)) {
                fclose($stream);
            }
        }
    }

    /**
     * Resolve the absolute on-disk path of a file, or null when it isn't stored
     * on a local filesystem the daemon can read (e.g. a cloud asset store), in
     * which case the caller falls back to streaming.
     */
    protected function getLocalFilesystemPath(File $file): ?string
    {
        $dbFile = $file->File;
        if (!$dbFile || !$dbFile->exists()) {
            return null;
        }

        try {
            $store = Injector::inst()->get(AssetStore::class);
            if (!$store instanceof FlysystemAssetStore) {
                return null;
            }

            $isProtected = $file->getVisibility() === AssetStore::VISIBILITY_PROTECTED;
            $filesystem = $isProtected
                ? $store->getProtectedFilesystem()
                : $store->getPublicFilesystem();
            $adapter = $filesystem->getAdapter();
            if (!$adapter instanceof LocalFilesystemAdapter) {
                return null;
            }

            $strategy = $isProtected
                ? $store->getProtectedResolutionStrategy()
                : $store->getPublicResolutionStrategy();
            $fileID = $strategy->buildFileID(
                new ParsedFileID($dbFile->Filename, $dbFile->Hash, $dbFile->Variant)
            );

            $path = $adapter->prefixPath($fileID);

            if (!is_file($path)) {
                return null;
            }

            // The path is sent to clamd as `SCAN <path>\n`. A newline or NUL in
            // the path could terminate/inject the clamd command, so refuse such
            // paths and let the caller stream instead. Asset-store paths never
            // legitimately contain control characters.
            if (preg_match('/[\x00-\x1f]/', $path) === 1) {
                return null;
            }

            return $path;
        } catch (\Throwable $e) {
            // Any resolution failure simply degrades to streaming.
            return null;
        }
    }

    /**
     * Flatten a Quahog result into the array persisted on ClamAVScan.RawData.
     */
    protected function normaliseScanResult(Result $result): array
    {
        $status = self::STATUS_OK;
        if ($result->isFound()) {
            $status = self::STATUS_FOUND;
        } elseif ($result->isError()) {
            $status = self::STATUS_ERROR;
        }

        return [
            'filename' => $result->getFilename(),
            'status' => $status,
            'reason' => $result->getReason(),
        ];
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
        // Distinct is resolved in SQL rather than pulling every row into PHP.
        $excludeFileIDs = ClamAVScan::get()->columnUnique('FileID');
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
        $fileIDs = $this->getFailedToScanScanList()->columnUnique('FileID');
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

    /**
     * Whether any file failed to scan (daemon down at upload time) and is still awaiting a scan.
     */
    public function hasFailedToScanFiles(): bool
    {
        return $this->getFailedToScanScanList()->exists();
    }

    /**
     * Base query for `ClamAVScan` records that represent an upload the daemon
     * couldn't scan and that hasn't been actioned yet.
     */
    protected function getFailedToScanScanList(): DataList
    {
        return ClamAVScan::get()->filter([
            'IsScanned' => 0,
            'Action' => ClamAVScan::ACTION_NONE,
            'FileID:not' => 0,
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
        } catch (Exception|ConnectionException $e) {
            $this->setLastExceptionAndLog($e);
            $version = self::OFFLINE;
        }

        return $version;
    }

    /**
     * Get the last exception caught by this.
     * Allows you to report the exact error to an admin/developer user in the CMS.
     */
    public function getLastException(): ?\Exception
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
            Injector::inst()->get(LoggerInterface::class)->warning('ClamAV: ' . $e->getMessage());
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

        return $request->getIP() ?? '';
    }
}
