<?php

namespace Symbiote\SteamedClams\Extension;

use SilverStripe\Assets\File;
use SilverStripe\Assets\Folder;
use SilverStripe\Control\Controller;
use SilverStripe\Core\Extension;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Core\Validation\ValidationResult;
use SilverStripe\ORM\DataList;
use SilverStripe\ORM\DataObject;
use Silverstripe\SiteConfig\SiteConfig;
use Symbiote\SteamedClams\ClamAV;
use Symbiote\SteamedClams\Model\ClamAVScan;

/**
 * Class Symbiote\SteamedClams\ClamAVExtension.
 *
 * @property ClamAVExtension|File $owner
 *
 * @method ClamAVScan[]|DataList ClamAVScans()
 */
class ClamAVExtension extends Extension
{
    protected $_cache_scanForVirus = 0;
    private static array $has_many = [
        'ClamAVScans' => ClamAVScan::class,
    ];

    // public function updateCMSFields(FieldList $fields) {
    // todo(Jake): Show 'ClamAVScans' on AssetAdmin/File level.
    // }

    /**
     * This is called within `File::write()` but before `File::onBeforeWrite()`.
     *
     * @param ValidationResult $validationResult
     *
     * @throws \SilverStripe\ORM\ValidationException
     */
    public function updateValidate(ValidationResult $validationResult): void
    {
        // If its a new file, scan it.
        $doVirusScan = ($this->owner->ID == 0);

        // Scan a file if it changed
        $changedFields = $this->owner->getChangedFields(true, DataObject::CHANGE_VALUE);
        foreach (['File', 'FileHash', 'Version', 'CurrentVersionID'] as $changeField) {
            if (isset($changedFields[$changeField]) && $changedFields[$changeField]['before'] !== $changedFields[$changeField]['after']) {
                $doVirusScan = true;

                break;
            }
        }

        // NOTE(Jake): Perhaps add $this->extend('updateDoVirusScan'); so other modules can support this.

        // Skip scanning unless the *physical* file on disk/CDN/etc has changed
        if (!$doVirusScan) {
            return;
        }

        $record = $this->owner->scanForVirus();

        if (!$record) {
            return;
        }

        $denyOnFailure = ClamAV::config()->get('deny_on_failure');

        $denyUpload = ($record->IsInfected || ($denyOnFailure && !$record->IsScanned));
        // todo(Jake): Allow for custom deny rules with virus scan and TEST.
        // $this->owner->extend('updateDeny', $denyUpload, $record, $validationResult);

        if (!$denyUpload) {
            // Add the scan/log if the file is clean / allowed
            $this->owner->ClamAVScans()->add($record);

            return;
        }

        $config = SiteConfig::current_site_config();

        $validationMessage = ($config->ValidationMessage) ? $config->ValidationMessage : 'A virus was detected.';

        $validationResult->addError(
            _t(
                'ClamAV.VIRUS_DETECTED',
                $validationMessage
            ),
            'VIRUS'
        );

        // Delete infected file
        // (If file hasn't been written to DB yet)
        if ($this->owner->ID == 0) {
            $this->owner->deleteFile();

            $record->Action = ClamAVScan::ACTION_DELETED;
        }

        // Write log of infection to DB
        // (as this File record will never be written due to failing
        //  validation)
        if ($record && !$record->exists()) {
            $record->write();
        }
    }

    /**
     * Returns an unsaved `ClamAVScan` record with information regarding the virus scan.
     */
    public function scanForVirus(): ?ClamAVScan
    {
        if (!$this->isVirusScannable()) {
            return null;
        }

        return Injector::inst()->get(ClamAV::class)->scanFileRecordForVirus($this->owner);
    }

    /**
     * Whether the file can be scanned or not.
     */
    public function isVirusScannable(): bool
    {
        if ($this->owner instanceof Folder) {
            return false;
        }

        // NOTE(Jake): Perhaps add $this->owner->extend() here? Maybe you want to avoid scanning
        // 2GB files or similar? But maybe we want a different function that works
        // like ::validate(). Too early to say.
        return true;
    }

    /**
     * Returns a source URL/path to the file based on the used assets store
     * Optionally removes any query params (e.g. when used with S3).
     *
     * @param bool $stripQueryParams
     *
     * @return null|string
     */
    public function getFullPath(bool $stripQueryParams = false): ?string
    {
        /** @var File $owner */
        $owner = $this->getOwner();

        if (!isset($owner->File)) {
            return null;
        }

        // getSourceURL() calls FlysystemAssetStore::grant() for protected files,
        // which requires an active controller/request. During dev/build with no
        // database no controller exists, so fall back to the stored filename
        // which is sufficient for the scan log record.
        if (!Controller::curr()) {
            return $owner->getFilename() ?: null;
        }

        $sourceUrl = $this->owner->File->getSourceURL() ?? '';
        if ($stripQueryParams) {
            return strtok($sourceUrl, '?') ?: null;
        }

        return $sourceUrl;
    }

    /**
     * @throws \SilverStripe\ORM\ValidationException
     */
    public function onAfterDelete(): void
    {
        foreach ($this->owner->ClamAVScans() as $scan) {
            $scan->processFileActionDelete();
        }
    }
}
