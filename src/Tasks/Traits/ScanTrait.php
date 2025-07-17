<?php

namespace Symbiote\SteamedClams\Tasks\Traits;

use Exception;
use SilverStripe\Model\List\SS_List;
use Symbiote\SteamedClams\ClamAV;

trait ScanTrait
{
    use LogTrait;

    /**
     * Limit the `File` lists for testing purposes.
     */
    protected int $default_limit = 0;

    /**
     * Scan files "bit-by-bit" to avoid filling up and blowing low memory limits.
     *
     * @throws Exception
     */
    protected function scanListChunked(SS_List $list, ?int $limit = null, int $chunkSize = 100): bool
    {
        if ($limit === null && $this->default_limit > 0) {
            $limit = $this->default_limit;
        }

        $totalCount = $list->count();
        if ($limit > 0) {
            if ($limit > $totalCount) {
                $limit = $totalCount;
            }
            if ($chunkSize > $limit) {
                $chunkSize = $limit;
            }
            $totalCount = $limit;
        }

        $offset = 0;
        while ($offset < $totalCount) {
            $subList = $list->limit($chunkSize, $offset);
            $offset += $chunkSize;
            if ($this->scanList($subList) === false) {
                return false;
            }
            gc_collect_cycles();
        }

        return true;
    }

    /**
     * @throws Exception
     */
    protected function scanList(SS_List $list): bool
    {
        foreach ($list as $file) {
            // Skip `Folder` type
            if (!$file->isVirusScannable()) {
                $this->log('Cannot scan this type, skipping ' . $file->ClassName . ' #' . $file->ID . '.');

                continue;
            }

            $path = $file->getFullPath();
            if (!$path) {
                $this->log('Skipping ' . $file->ClassName . ' #' . $file->ID . ', no path on record. getFullPath = "' . $path . '"');

                continue;
            }
            $logRecord = $file->scanForVirus();

            // scans by a job/task will have an IPAddress of 127.0.0.1
            $originalScan = $file->ClamAVScans()->sort('Created DESC')->first();
            if (isset($originalScan, $originalScan->IPAddress)) {
                // replace 127.0.0.1 with original IPAddress
                $logRecord->IPAddress = $originalScan->IPAddress;
            }

            if ($logRecord === ClamAV::OFFLINE) {
                $this->log('ClamAV daemon is offline.', 'error');

                return false;
            }
            if (!$logRecord) {
                $this->log('Skipping ' . $file->ClassName . ' #' . $file->ID . '. File doesn\'t exist.');

                continue;
            }
            if ($logRecord->IsInfected) {
                $this->log($file->ClassName . ' #' . $file->ID . ' has a virus.', 'error');
            } else {
                $this->log($file->ClassName . ' #' . $file->ID . ' is clean.', 'created');
            }
            $logRecord->write();
        }

        return true;
    }
}
