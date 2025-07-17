<?php

namespace Symbiote\SteamedClams\Extension;

use SilverStripe\Core\Extension;
use Symbiote\SteamedClams\Model\ClamAVScan;

/**
 * Hides Clam AV Scans from file used on table.
 */
class ClamAVUsedOnTableExtension extends Extension
{
    /**
     * @param mixed $excludedClasses
     * @var string[]
     *
     */
    public function updateUsageExcludedClasses(&$excludedClasses): void
    {
        $excludedClasses[] = ClamAVScan::class;
    }
}
