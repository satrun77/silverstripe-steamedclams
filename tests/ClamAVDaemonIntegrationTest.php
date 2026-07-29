<?php

namespace Symbiote\SteamedClams\Tests;

use SilverStripe\Assets\Dev\TestAssetStore;
use SilverStripe\Assets\File;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Core\Validation\ValidationException;
use SilverStripe\Dev\SapphireTest;
use Symbiote\SteamedClams\ClamAV;
use Symbiote\SteamedClams\Model\ClamAVScan;

/**
 * End-to-end scan against a REAL clamd daemon.
 *
 * Skipped automatically unless a clamd unix socket is reachable, so it never
 * runs in CI. To run locally, start clamd and point CLAMAV_TEST_SOCKET (or the
 * default below) at its LocalSocket.
 */
class ClamAVDaemonIntegrationTest extends SapphireTest
{
    // phpcs:disable
    protected $usesDatabase = true;
    // phpcs:enable

    private const DEFAULT_SOCKET = '/tmp/clamd.socket';

    // Standard EICAR anti-virus test signature (harmless, detected by all AV).
    private const EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

    protected function setUp(): void
    {
        parent::setUp();

        $socket = getenv('CLAMAV_TEST_SOCKET') ?: self::DEFAULT_SOCKET;
        if (!file_exists($socket)) {
            $this->markTestSkipped('No clamd socket at ' . $socket);
        }

        TestAssetStore::activate('ClamAVIntegration');
        Config::modify()->set(ClamAV::class, 'clamd', ['LocalSocket' => $socket]);
        Config::modify()->set(ClamAV::class, 'deny_on_failure', false);

        // Use the real ClamAV service (not the emulator).
        Injector::inst()->registerService(new ClamAV(), ClamAV::class);
    }

    protected function tearDown(): void
    {
        TestAssetStore::reset();
        parent::tearDown();
    }

    public function testDaemonIsOnline(): void
    {
        $version = Injector::inst()->get(ClamAV::class)->version();
        $this->assertNotSame(ClamAV::OFFLINE, $version, 'clamd should report a version');
        $this->assertStringContainsStringIgnoringCase('clamav', (string)$version);
    }

    public function testDetectsEicarVirus(): void
    {
        $fileCount = File::get()->count();

        $file = File::create();
        $file->setFromString(self::EICAR, 'eicar.txt');

        $blocked = false;
        try {
            $file->write();
        } catch (ValidationException $e) {
            $blocked = true;
        }

        $this->assertTrue($blocked, 'Infected file must be blocked on write');
        $this->assertEquals($fileCount, File::get()->count(), 'Infected file must not persist');

        $scan = ClamAVScan::get()->sort('ID', 'DESC')->first();
        $this->assertNotNull($scan);
        $this->assertEquals(1, (int)$scan->IsScanned);
        $this->assertEquals(1, (int)$scan->IsInfected, 'EICAR must be detected as infected');
    }

    public function testCleanFilePassesAndIsLogged(): void
    {
        $file = File::create();
        $file->setFromString('a genuinely clean file', 'clean.txt');
        $file->write();

        $this->assertTrue($file->exists(), 'Clean file should persist');

        $scan = $file->ClamAVScans()->first();
        $this->assertNotNull($scan, 'A scan record should be logged for the clean file');
        $this->assertEquals(1, (int)$scan->IsScanned);
        $this->assertEquals(0, (int)$scan->IsInfected);

        // On a local asset store the daemon should read the file by path (SCAN),
        // which is what lifts the INSTREAM StreamMaxLength ceiling. Path scans
        // echo the real path back; INSTREAM would report the filename "stream".
        $raw = $scan->getRawData();
        $this->assertNotEmpty($raw['filename'] ?? null);
        $this->assertNotSame('stream', $raw['filename'], 'Local files should scan by path, not INSTREAM');
    }

    public function testScansFileLargerThanStreamDefaultLimit(): void
    {
        // ~2MB clean file: proves real files (not just a few bytes) scan through
        // the resolved path/stream without the module buffering them in memory.
        $content = str_repeat('SteamedClams clean payload 0123456789 ', 55000);
        $file = File::create();
        $file->setFromString($content, 'large-clean.txt');
        $file->write();

        $this->assertTrue($file->exists());
        $scan = $file->ClamAVScans()->first();
        $this->assertNotNull($scan);
        $this->assertEquals(1, (int)$scan->IsScanned);
        $this->assertEquals(0, (int)$scan->IsInfected);
    }
}
