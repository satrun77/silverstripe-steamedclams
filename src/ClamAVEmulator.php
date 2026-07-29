<?php

namespace Symbiote\SteamedClams;

use LogicException;
use SilverStripe\Assets\File;
use SilverStripe\Core\Config\Config;
use Xenolope\Quahog\Exception\ConnectionException;
use Xenolope\Quahog\Result;

/**
 * For emulating/faking ClamAV results.
 *
 * This was implemented so Windows users and inexperienced developers can
 * focus on the logic surrounding the ClamAV daemon, without needing to
 * know how install it.
 */
class ClamAVEmulator extends ClamAV
{
    public const int MODE_UNKNOWN = 0;
    public const int MODE_NO_VIRUS = 1;
    public const int MODE_HAS_VIRUS = 2;
    public const int MODE_OFFLINE = 3;

    /**
     * The daemon is online but returned a scan error for the file
     * (e.g. clamd's stream/file size limit was reached).
     */
    public const int MODE_SCAN_ERROR = 4;

    /**
     * The state of ClamAV to fake.
     */
    private static int $mode = self::MODE_UNKNOWN;

    /**
     * The version string to return when emulating.
     *
     * @var string
     */
    private static string $emulate_version = 'ClamAV 0.99.2/22585/Wed Nov 23 00:21:08 2016';

    /**
     * {@inheritDoc}
     */
    public function version(): bool|string
    {
        $mode = Config::inst()->get(__CLASS__, 'mode');
        $emulateVersion = Config::inst()->get(__CLASS__, 'emulate_version');

        switch ($mode) {
            case self::MODE_UNKNOWN:
                return $this->modeUnknown();

            case self::MODE_NO_VIRUS:
            case self::MODE_HAS_VIRUS:
            case self::MODE_SCAN_ERROR:
                return $emulateVersion;

            case self::MODE_OFFLINE:
                return $this->modeOffline();

            default:
                return $this->modeInvalid();
        }
    }

    /**
     * Fake the daemon scan seam so the surrounding upload/deny/log logic can be
     * exercised without a real ClamAV daemon or socket.
     *
     * {@inheritDoc}
     */
    protected function getClamdScan(File $file): ?Result
    {
        $mode = Config::inst()->get(__CLASS__, 'mode');
        $filename = $file->getFullPath(true) ?: 'stream';

        switch ($mode) {
            case self::MODE_NO_VIRUS:
                return new Result(self::STATUS_OK, $filename, null, null);

            case self::MODE_HAS_VIRUS:
                return new Result(self::STATUS_FOUND, $filename, 'Eicar-Test-Signature FOUND', null);

            case self::MODE_SCAN_ERROR:
                return new Result(self::STATUS_ERROR, $filename, 'INSTREAM: Size limit reached. ERROR', null);

            case self::MODE_OFFLINE:
                // Mirror a real socket failure so scanFileForVirus() records the
                // file as "unscanned" and logs the reason.
                throw new ConnectionException($this->offlineMessage());

            case self::MODE_UNKNOWN:
                return $this->modeUnknown();

            default:
                return $this->modeInvalid();
        }
    }

    protected function modeUnknown(): never
    {
        throw new LogicException('Must configure ' . __CLASS__ . '::mode config');
    }

    protected function modeOffline(): bool
    {
        $this->last_exception = new ConnectionException($this->offlineMessage(), 2);

        return self::OFFLINE;
    }

    protected function modeInvalid(): never
    {
        throw new LogicException(
            'Invalid "mode" config with value "' . Config::inst()->get(__CLASS__, 'mode')
            . '". Use constants provided in ' . __CLASS__ . ' class.'
        );
    }

    private function offlineMessage(): string
    {
        return '*EMULATE MODE* No such file or directory "/not-real-root-folder/run/clamav/clamd.ctl"';
    }
}
