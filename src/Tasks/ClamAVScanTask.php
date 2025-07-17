<?php

namespace Symbiote\SteamedClams\Tasks;

use SilverStripe\Dev\BuildTask;
use SilverStripe\PolyExecution\PolyOutput;
use Symbiote\SteamedClams\Tasks\Traits\ClamAVTrait;
use Symbiote\SteamedClams\Tasks\Traits\LogTrait;
use Symbiote\SteamedClams\Tasks\Traits\ScanTrait;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;

class ClamAVScanTask extends BuildTask
{
    use ClamAVTrait;
    use LogTrait;
    use ScanTrait;

    protected static string $commandName = 'clamav-scan';

    protected string $title = 'ClamAV Virus Scan Task';

    protected static string $description = 'Scans files missed due to ClamAV daemon being unavailable at time of file upload.';

    protected function execute(InputInterface $input, PolyOutput $output): int
    {
        if (!$this->isOnline()) {
            return Command::INVALID;
        }

        $this->log('Starting ClamAV task...');

        $list = $this->getClamAV()->getFailedToScanFileList();
        $listCount = $list->count();
        if ($listCount > 0) {
            $this->log('------------------------------------');
            $this->log('Scanning the ' . $listCount . ' files that couldn\'t be scanned due 
            to previous ClamAV daemon connectivity issues.');
            $this->log('------------------------------------');
            $this->scanListChunked($list, $this->debug_limit);
            $this->log('Finished ClamAV task.');
        } else {
            $this->log('Finished ClamAV task. No action was required.');
        }

        return Command::SUCCESS;
    }
}
