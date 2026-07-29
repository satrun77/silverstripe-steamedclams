<?php

namespace Symbiote\SteamedClams\Tests;

use SilverStripe\Assets\Flysystem\ProtectedAssetAdapter;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use Symbiote\SteamedClams\ClamAV;
use Symbiote\SteamedClams\ClamAVEmulator;
use Symbiote\SteamedClams\Model\ClamAVScan;
use SilverStripe\Assets\File;
use SilverStripe\Core\Validation\ValidationException;
use SilverStripe\Assets\Dev\TestAssetStore;
use SilverStripe\Security\BasicAuth;
use SilverStripe\Core\Config\Config;

class ClamAVExtensionTest extends SapphireTest
{
    protected $usesDatabase = true;

    public function setUp(): void
    {
        parent::setUp();

        TestAssetStore::activate('UploadTest');
        BasicAuth::config()->set('ignore_cli', false);

        $clamAV = new ClamAVEmulator();
        Injector::inst()->registerService($clamAV, ClamAV::class);
    }

    //protected static $fixture_file = 'ClamAVExtensionTest.yml';

    protected function getMockFile($name = 'test-file.txt'): string
    {
        $absoluteTmpPath = TestAssetStore::base_path() . DIRECTORY_SEPARATOR . $name;
        file_put_contents($absoluteTmpPath, 'testtext');

        return $absoluteTmpPath;
    }

    /**
     *
     */
    public function testBlockFileWriteIfVirusAndDenyOnFailure(): void
    {
        ClamAVEmulator::config()->set('mode', ClamAVEmulator::MODE_HAS_VIRUS);
        ClamAV::config()->set('deny_on_failure', true);

        $scanCount = ClamAVScan::get()->count();

        $name = 'updated-file.txt';
        $fileCount = File::get()->count();
        $record = File::create();
        $record->File->setFromLocalFile($this->getMockFile($name), $name);

        try {
            $record->write();
        } catch (ValidationException $e) {
            //
        }

        // Ensure only one scan file gets created
        $this->assertEquals($scanCount + 1, ClamAVScan::get()->count());

        // Ensure no file got created if it had a virus
        $this->assertEquals($fileCount, File::get()->count());
    }

    public function testInfectedFileIsAlwaysBlockedAndLogged(): void
    {
        // An infected file must be blocked regardless of deny_on_failure, which
        // only governs the "daemon unreachable" case.
        ClamAVEmulator::config()->set('mode', ClamAVEmulator::MODE_HAS_VIRUS);
        ClamAV::config()->set('deny_on_failure', false);

        $name = 'updated-file.txt';

        $fileCount = File::get()->count();
        $scanCount = ClamAVScan::get()->count();
        $record = File::create();
        $record->File->setFromLocalFile($this->getMockFile($name), $name);

        try {
            $record->write();
        } catch (ValidationException $e) {
            //
        }

        // Ensure scan is created and correctly flagged as an infection
        $this->assertEquals($scanCount + 1, ClamAVScan::get()->count());
        $scan = ClamAVScan::get()->sort('ID', 'DESC')->first();
        $this->assertEquals(1, (int)$scan->IsScanned, 'A found virus is a completed scan');
        $this->assertEquals(1, (int)$scan->IsInfected, 'The scan must be flagged as infected');

        // Ensure the infected file was NOT created
        $this->assertEquals($fileCount, File::get()->count());
    }

    public function testCleanFileIsAllowedAndLogged(): void
    {
        ClamAVEmulator::config()->set('mode', ClamAVEmulator::MODE_NO_VIRUS);
        ClamAV::config()->set('deny_on_failure', true);

        $name = 'updated-file.txt';

        $fileCount = File::get()->count();
        $scanCount = ClamAVScan::get()->count();
        $record = File::create();
        $record->File->setFromLocalFile($this->getMockFile($name), $name);
        $record->write();

        // A clean file is allowed through and its scan logged as clean
        $this->assertEquals($fileCount + 1, File::get()->count());
        $this->assertEquals($scanCount + 1, ClamAVScan::get()->count());
        $scan = $record->ClamAVScans()->first();
        $this->assertNotNull($scan, 'The clean scan is attached to the file');
        $this->assertEquals(1, (int)$scan->IsScanned);
        $this->assertEquals(0, (int)$scan->IsInfected);
    }

    public function testOfflineWithDenyOnFailureBlocksFile(): void
    {
        // When the daemon is unreachable and deny_on_failure is on, the upload
        // is denied even though no infection could be confirmed.
        ClamAVEmulator::config()->set('mode', ClamAVEmulator::MODE_OFFLINE);
        ClamAV::config()->set('deny_on_failure', true);

        $name = 'updated-file.txt';

        $fileCount = File::get()->count();
        $scanCount = ClamAVScan::get()->count();
        $record = File::create();
        $record->File->setFromLocalFile($this->getMockFile($name), $name);

        try {
            $record->write();
        } catch (ValidationException $e) {
            //
        }

        $this->assertEquals($scanCount + 1, ClamAVScan::get()->count());
        $scan = ClamAVScan::get()->sort('ID', 'DESC')->first();
        $this->assertEquals(0, (int)$scan->IsScanned, 'Offline means the file was never scanned');
        $this->assertEquals($fileCount, File::get()->count(), 'deny_on_failure blocks the unscanned upload');
    }

    public function testFileLogIfVirusScannerOffline(): void
    {
        ClamAVEmulator::config()->set('mode', ClamAVEmulator::MODE_OFFLINE);
        ClamAV::config()->set('deny_on_failure', false);

        $name = 'updated-file.txt';

        $scanCount = ClamAVScan::get()->count();
        $record = File::create();
        $record->Name = $name;
        $record->File->setFromLocalFile($this->getMockFile($name), $name);

        try {
            $record->write();
        } catch (ValidationException $e) {
            //
        }

        // Ensure scan is created
        $this->assertEquals($scanCount + 1, ClamAVScan::get()->count());

        // Ensure file gets created regardless of whether it has a virus
        $this->assertEquals(1, File::get()->count());
    }

    public function testScanErrorIsNotTreatedAsInfection(): void
    {
        // Regression: a clamd scan error (e.g. size limit reached) must be
        // recorded as "unscanned" so it is retried, and must never block the
        // upload as if the file were infected.
        ClamAVEmulator::config()->set('mode', ClamAVEmulator::MODE_SCAN_ERROR);
        ClamAV::config()->set('deny_on_failure', false);

        $name = 'updated-file.txt';

        $fileCount = File::get()->count();
        $scanCount = ClamAVScan::get()->count();
        $record = File::create();
        $record->File->setFromLocalFile($this->getMockFile($name), $name);
        $record->write();

        $this->assertEquals($scanCount + 1, ClamAVScan::get()->count());
        $scan = ClamAVScan::get()->sort('ID', 'DESC')->first();
        $this->assertEquals(0, (int)$scan->IsScanned, 'A scan error is not a completed scan');
        $this->assertEquals(0, (int)$scan->IsInfected, 'A scan error is not an infection');

        // File is allowed through (not blocked) because it was not confirmed infected
        $this->assertEquals($fileCount + 1, File::get()->count());
    }

    public function testFilesAreNeverSkippedBySize(): void
    {
        // The module must not impose its own file-size gate; every non-folder
        // file is scannable regardless of size.
        $file = File::create();
        $this->assertTrue($file->isVirusScannable());
    }

    public function testPhysicalFileRemovalOnNewFileRecordIfDenied(): void
    {
        ClamAVEmulator::config()->set('mode', ClamAVEmulator::MODE_HAS_VIRUS);
        ClamAV::config()->set('deny_on_failure', true);

        $filename = 'clamav_' . __FUNCTION__ . '.txt';
        $filepath = TestAssetStore::base_path() . DIRECTORY_SEPARATOR . $filename;

        $this->assertFalse(file_exists($filepath));
        file_put_contents($filepath, 'testtext');

        $this->assertTrue(file_exists($filepath));

        $record = File::create();
        $record->File->setFromLocalFile($filepath, $filename);

        $newFilepath = TestAssetStore::base_path() . '/' . Config::inst()->get(ProtectedAssetAdapter::class, 'secure_folder')
            . '/'. $record->File->getFilename();

        try {
            $record->write();
        } catch (ValidationException $e) {
            //
        }

        // Ensure the file is removed during File::validate()
        $fileExists = file_exists($newFilepath);
        // Cleanup from file system for local testing reasons
        @unlink($filepath);
        $this->assertFalse($fileExists);
    }

    public function testPhysicalFileRemovalOnNewFileRecordIfNotDenied(): void
    {
        ClamAVEmulator::config()->set('mode', ClamAVEmulator::MODE_HAS_VIRUS);
        ClamAV::config()->set('deny_on_failure', false);

        $filename = 'clamav_' . __FUNCTION__ . '.txt';
        $filepath = TestAssetStore::base_path() . DIRECTORY_SEPARATOR . $filename;
        // Ensure file didn't already exist on system
        $this->assertFalse(file_exists($filepath));
        file_put_contents($filepath, 'testtext');
        $this->assertTrue(file_exists($filepath));

        $record = File::create();
        $record->Filename = TestAssetStore::base_path() . '/' . $filename;
        try {
            $record->write();
        } catch (ValidationException $e) {
        }

        // Ensure the file stays if not denying files
        $fileExists = file_exists($filepath);
        // Cleanup from file system for local testing reasons
        @unlink($filepath);
        $this->assertTrue($fileExists);
    }
}
