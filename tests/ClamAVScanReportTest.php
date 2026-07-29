<?php

namespace Symbiote\SteamedClams\Tests;

use SilverStripe\Dev\SapphireTest;
use SilverStripe\Security\Member;
use Symbiote\SteamedClams\Model\ClamAVScan;
use Symbiote\SteamedClams\Reports\ClamAVScanReport;

/**
 * Regression coverage for the ClamAVScanReport parameter filters, which
 * previously excluded (rather than filtered) date ranges and treated the
 * dropdown "All" option as a real value.
 */
class ClamAVScanReportTest extends SapphireTest
{
    // phpcs:disable
    protected $usesDatabase = true;
    // phpcs:enable

    private function makeScan(array $data, string $created): ClamAVScan
    {
        $scan = ClamAVScan::create();
        $scan->update($data);
        $scan->Created = $created;
        $scan->write();

        return $scan;
    }

    private function ids(iterable $list): array
    {
        $ids = [];
        foreach ($list as $item) {
            $ids[] = (int)$item->ID;
        }
        sort($ids);

        return $ids;
    }

    public function testNoParamsReturnsEverything(): void
    {
        $a = $this->makeScan(['IsScanned' => 1, 'Action' => ClamAVScan::ACTION_NONE], '2026-01-01 10:00:00');
        $b = $this->makeScan(['IsScanned' => 0, 'Action' => ClamAVScan::ACTION_DELETED], '2026-02-01 10:00:00');

        $report = new ClamAVScanReport();
        $this->assertEquals([$a->ID, $b->ID], $this->ids($report->sourceRecords([])));
    }

    public function testAllOptionDoesNotFilterToZeroValues(): void
    {
        // The dropdown "All" option submits an empty string. It must return
        // every record, not silently pin to Action=0 / IsScanned=0.
        $none = $this->makeScan(['IsScanned' => 1, 'Action' => ClamAVScan::ACTION_NONE], '2026-01-01 10:00:00');
        $deleted = $this->makeScan(['IsScanned' => 1, 'Action' => ClamAVScan::ACTION_DELETED], '2026-01-02 10:00:00');

        $report = new ClamAVScanReport();
        $params = ['Action' => '', 'IsScanned' => '', 'MemberID' => '', 'CreatedFrom' => '', 'CreatedTo' => ''];
        $this->assertEquals([$none->ID, $deleted->ID], $this->ids($report->sourceRecords($params)));
    }

    public function testActionZeroIsAValidFilter(): void
    {
        // ACTION_NONE is 0 — selecting it must return only those records.
        $none = $this->makeScan(['Action' => ClamAVScan::ACTION_NONE], '2026-01-01 10:00:00');
        $this->makeScan(['Action' => ClamAVScan::ACTION_DELETED], '2026-01-02 10:00:00');

        $report = new ClamAVScanReport();
        $result = $report->sourceRecords(['Action' => (string)ClamAVScan::ACTION_NONE]);
        $this->assertEquals([$none->ID], $this->ids($result));
    }

    public function testIsScannedFilter(): void
    {
        $scanned = $this->makeScan(['IsScanned' => 1], '2026-01-01 10:00:00');
        $unscanned = $this->makeScan(['IsScanned' => 0], '2026-01-02 10:00:00');

        $report = new ClamAVScanReport();
        $this->assertEquals([$unscanned->ID], $this->ids($report->sourceRecords(['IsScanned' => '0'])));
        $this->assertEquals([$scanned->ID], $this->ids($report->sourceRecords(['IsScanned' => '1'])));
    }

    public function testMemberFilter(): void
    {
        $member = Member::create();
        $member->write();

        $mine = $this->makeScan(['MemberID' => $member->ID], '2026-01-01 10:00:00');
        $this->makeScan(['MemberID' => 0], '2026-01-02 10:00:00');

        $report = new ClamAVScanReport();
        $result = $report->sourceRecords(['MemberID' => (string)$member->ID]);
        $this->assertEquals([$mine->ID], $this->ids($result));
    }

    public function testDateRangeFiltersInsteadOfExcluding(): void
    {
        $jan = $this->makeScan([], '2026-01-15 10:00:00');
        $feb = $this->makeScan([], '2026-02-15 10:00:00');
        $mar = $this->makeScan([], '2026-03-15 10:00:00');

        $report = new ClamAVScanReport();

        // From only
        $this->assertEquals([$feb->ID, $mar->ID], $this->ids($report->sourceRecords(['CreatedFrom' => '2026-02-01'])));
        // To only
        $this->assertEquals([$jan->ID, $feb->ID], $this->ids($report->sourceRecords(['CreatedTo' => '2026-02-28'])));
        // Range
        $range = $report->sourceRecords(['CreatedFrom' => '2026-02-01', 'CreatedTo' => '2026-02-28']);
        $this->assertEquals([$feb->ID], $this->ids($range));
    }

    public function testToDateIsInclusiveOfWholeDay(): void
    {
        $sameDayLater = $this->makeScan([], '2026-02-15 23:30:00');

        $report = new ClamAVScanReport();
        $result = $report->sourceRecords(['CreatedTo' => '2026-02-15']);
        $this->assertEquals([$sameDayLater->ID], $this->ids($result));
    }
}
