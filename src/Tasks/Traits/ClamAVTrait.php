<?php

namespace Symbiote\SteamedClams\Tasks\Traits;

use SilverStripe\Core\Injector\Injector;
use Symbiote\SteamedClams\ClamAV;

trait ClamAVTrait
{
    use LogTrait;

    protected ?ClamAV $clamAV = null;

    /**
     * Limit the `File` lists for testing purposes.
     */
    protected int $debug_limit = 0;

    protected function getClamAV(): ClamAV
    {
        // Check if online before starting
        if (is_null($this->clamAV)) {
            $this->clamAV = Injector::inst()->get(ClamAV::class);
        }

        return $this->clamAV;
    }

    protected function isOnline(): bool
    {
        $version = $this->getClamAV()->version();
        if ($version === ClamAV::OFFLINE) {
            $this->log('ClamAV daemon is offline. Cannot scan.');

            return false;
        }

        return true;
    }
}
