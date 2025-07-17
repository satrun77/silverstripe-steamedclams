<?php

namespace Symbiote\SteamedClams\Tasks;

use SilverStripe\Dev\BuildTask;
use SilverStripe\PolyExecution\PolyOutput;
use Symbiote\SteamedClams\Tasks\Traits\ClamAVTrait;
use Symbiote\SteamedClams\Tasks\Traits\LogTrait;
use Symbiote\SteamedClams\Tasks\Traits\ScanTrait;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;

class ClamAVInstallTask extends BuildTask
{
    use ClamAVTrait;
    use LogTrait;
    use ScanTrait;

    protected static string $commandName = 'clamav-install';

    protected string $title = 'ClamAV Virus Install Task';

    protected static string $description = 'Scans all files that haven\'t been scanned yet and aren\'t queued for later scanning.';

    protected function execute(InputInterface $input, PolyOutput $output): int
    {
        if (!$this->isOnline()) {
            return Command::INVALID;
        }

        $this->log('Starting ClamAV install task...');

        $list = $this->getClamAV()->getInitialFileToScanList();
        $listCount = $list->count();
        if ($listCount > 0) {
            $this->log('------------------------------------');
            $this->log('Scanning the ' . $listCount . ' files that were uploaded before module installation');
            $this->log('------------------------------------');
            $this->scanListChunked($list);
            $this->log('Finished ClamAV task.');
        } else {
            $this->log('Finished ClamAV task. No action was required.');
        }

        return Command::SUCCESS;
    }
}
