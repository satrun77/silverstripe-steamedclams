<?php

namespace Symbiote\SteamedClams;

use ClamdSocketException;
use LogicException;
use SilverStripe\Assets\File;
use SilverStripe\Core\Config\Config;
use SilverStripe\ORM\DataObject;
use Symbiote\SteamedClams\Model\ClamAVScan;

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

                break;

            case self::MODE_NO_VIRUS:
            case self::MODE_HAS_VIRUS:
                return $emulateVersion;

                break;

            case self::MODE_OFFLINE:
                return $this->modeOffline();

                break;

            default:
                return $this->modeInvalid();

                break;
        }
    }

    public function scanFileRecordForVirus(File $file): ?ClamAVScan
    {
        $record = $this->scanFileForVirus($file);
        if ($record && $record instanceof DataObject) {
            $record->FileID = $file->ID;
        }

        return $record;
    }

    /**
     * {@inheritDoc}
     */
    protected function fileScan(string $filepath): mixed
    {
        $mode = Config::inst()->get(__CLASS__, 'mode');

        switch ($mode) {
            case self::MODE_UNKNOWN:
                return $this->modeUnknown();

                break;

            case self::MODE_NO_VIRUS:
                return [
                    'file' => $filepath,
                    'stats' => 'OK',
                ];

                break;

            case self::MODE_HAS_VIRUS:
                return [
                    'file' => $filepath,
                    'stats' => 'Eicar-Test-Signature FOUND',
                ];

                break;

            case self::MODE_OFFLINE:
                return $this->modeOffline();

                break;

            default:
                return $this->modeInvalid();

                break;
        }
    }

    protected function modeUnknown()
    {
        throw new LogicException('Must configure ' . __CLASS__ . '::mode config');
    }

    protected function modeOffline(): bool
    {
        $this->last_exception = new ClamdSocketException(
            '*EMULATE MODE* No such file or directory "/not-real-root-folder/run/clamav/clamd.ctl"',
            2
        );

        return self::OFFLINE;
    }

    protected function modeInvalid()
    {
        throw new LogicException(
            'Invalid "mode" config with value "' . Config::inst()->get(__CLASS__, 'mode')
            . '". Use constants provided in ' . __CLASS__ . ' class.'
        );
    }
}
