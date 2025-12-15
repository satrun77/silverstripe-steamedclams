<?php

namespace Symbiote\SteamedClams\Model;

use JsonException;
use LogicException;
use Page;
use SilverStripe\Admin\LeftAndMain;
use SilverStripe\Assets\File;
use SilverStripe\CMS\Controllers\ContentController;
use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Core\Validation\ValidationException;
use SilverStripe\Forms\NumericField;
use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\FieldType\DBHTMLText;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;
use Symbiote\SteamedClams\Jobs\ClamAVScanJob;

/**
 * Class Symbiote\SteamedClams\ClamAVScan.
 *
 * @property string $Filename
 * @property string $ContextURL
 * @property bool $IsScanned
 * @property bool $IsInfected
 * @property int $Action
 * @property string $IPAddress
 * @property array $RawData
 * @property int $ContextPageID
 * @property int $FileID
 * @property int $MemberID
 * @property int $ActionMemberID
 *
 * @method Page   ContextPage()
 * @method File   File()
 * @method Member Member()
 * @method Member ActionMember()
 */
class ClamAVScan extends DataObject
{
    // This *should not* be stored in DB, number order can be modified.
    public const STATE_INVALID = 0;
    public const STATE_UNSCANNED = 1;
    public const STATE_INFECTED = 2;
    public const STATE_CLEAN = 3;
    public const STATE_DELETED_INFECTED = 4;
    public const STATE_DELETED_CLEAN = 5;
    public const STATE_DELETED_UNSCANNED = 6;
    public const STATE_IGNORED_INFECTED = 7;
    public const STATE_IGNORED_UNSCANNED = 8;

    // This is stored in the DB, do not modify number order.
    public const ACTION_NONE = 0;
    public const ACTION_DELETED = 1;
    public const ACTION_IGNORED = 2;

    /**
     * {@inheritDoc}
     */
    private static string $table_name = 'ClamAVScan';

    private static array $db = [
        'Filename' => 'Text',
        'ContextURL' => 'Text',
        'IsScanned' => 'Boolean',
        'IsInfected' => 'Boolean',
        'Action' => 'Int',
        'IPAddress' => 'Varchar(20)',
        'RawData' => 'Text',
    ];

    private static array $has_one = [
        'ContextPage' => Page::class,
        'File' => File::class,
        'Member' => Member::class,
        'ActionMember' => Member::class,
        // todo(Jake): Log 'ActionMember', the member who manually ran a 'Scan' or 'Ignore' action.
    ];

    /**
     * @var array
     */
    private static array $summary_fields = [
        'UserIdentifier' => 'User Identifier',
        'FileID' => [
            'title' => 'File ID',
            'callback' => [ClamAVScan::class, 'get_file_id_cms_link'],
        ],
        'Filename' => 'File Name',
        'LocationUploaded' => 'Location Uploaded',
        'StateMessage' => 'State',
        'RawDataSummary' => 'Virus Scan Info.',
        'Created' => 'Date Scanned',
    ];

    private static array $searchable_fields = [
        'MemberID' => [
            'title' => 'Member ID',
            'field' => NumericField::class,
        ],
        'FileID' => [
            'title' => 'File ID',
            'field' => NumericField::class,
        ],
        'IPAddress' => [
            'title' => 'IP Address',
        ],
        'Filename' => [
            'title' => 'Filename',
        ],
        'IsScanned' => [
            'title' => 'Is Scanned?',
        ],
        'IsInfected' => [
            'title' => 'Is Infected?',
        ],
        'RawData' => [
            'title' => 'Virus Scan Info.',
        ],
        'Created' => [
            'title' => 'Date Scanned',
        ],
    ];

    private static array $state_messages = [
        self::STATE_INVALID => [
            'type' => 'bad',
            'message' => 'Invalid',
        ],
        self::STATE_UNSCANNED => [
            'type' => 'warning',
            'message' => 'Needs to be scanned',
        ],
        self::STATE_INFECTED => [
            'type' => 'bad',
            'message' => 'Infected, Pending Action',
        ],
        self::STATE_CLEAN => [
            'type' => 'good',
            'message' => 'Clean',
        ],
        self::STATE_DELETED_INFECTED => [
            'type' => 'good',
            'message' => 'Deleted, File was infected',
        ],
        self::STATE_DELETED_CLEAN => [
            'type' => 'good',
            'message' => 'Deleted, File was clean',
        ],
        self::STATE_DELETED_UNSCANNED => [
            'type' => 'good',
            'message' => 'Deleted, File was never scanned',
        ],
        self::STATE_IGNORED_INFECTED => [
            'type' => 'good',
            'message' => 'Ignore infection',
        ],
        self::STATE_IGNORED_UNSCANNED => [
            'type' => 'good',
            'message' => 'Ignore unscanned',
        ],
    ];

    private static string $singular_name = 'ClamAV Scan';

    private static string $default_sort = 'ID DESC';

    public static function get_file_id_cms_link(ClamAVScan $record): DBHTMLText|int|string
    {
        if (!$record) {
            return '';
        }

        return $record->getFileIDCMSLink();
    }

    public function getFileIDCMSLink(): DBHTMLText|int
    {
        if (!$this->FileID) {
            return 0;
        }
        $file = $this->File();
        $fileID = (int)$this->FileID;
        if (!$file->exists() || !$file->canEdit()) {
            return $fileID;
        }
        $cmsEditLink = $file->getCMSEditLink();
        $result = DBHTMLText::create('FileID');
        $result->setValue($fileID);
        $result->setValue($result->getValue() . ' <a href="' . $cmsEditLink . '">(Edit)</a>');

        return $result;
    }

    public function requireDefaultRecords(): void
    {
        parent::requireDefaultRecords();
        if ($this->class !== __CLASS__) {
            return;
        }
        if (class_exists(ClamAVScanJob::class)) {
            Injector::inst()->get(ClamAVScanJob::class)->requireDefaultRecords();
        }
    }

    public function onBeforeWrite(): void
    {
        parent::onBeforeWrite();

        // If not written yet, apply defaults
        if (!$this->exists()) {
            // Store Member that is running the scan
            if (!$this->MemberID) {
                if (Director::is_cli()) {
                    // NOTE(Jake): We don't want scans done during cron/queuedjobs
                    // to log the Member, as technically no Member
                    // technically triggered the behaviour.
                    $this->MemberID = 0;
                } else {
                    $member = Security::getCurrentUser();
                    if ($member) {
                        $this->MemberID = $member->ID;
                    }
                    $this->MemberID = 0;
                }
            }

            $lastScan = ClamAVScan::get()->filter([
                'IsScanned' => 0,
                'Action' => ClamAVScan::ACTION_NONE,
                'FileID' => $this->FileID,
            ]);
            $lastScan = $lastScan->sort('ID', 'DESC');
            $lastScan = $lastScan->first();
            if ($lastScan) {
                // If a scan log exists where the scan failed due to the daemon being
                // down, bring its upload context information across.
                $inheritFields = [
                    'ContextURL',
                    'ContextPageID',
                ];
                foreach ($inheritFields as $inheritField) {
                    if ($this->{$inheritField}) {
                        // Skip values that have been set manually
                        continue;
                    }
                    $inheritValue = $lastScan->getField($inheritField);
                    $this->setField($inheritField, $inheritValue);
                }
            } else {
                // Store Context URL (where this was created)
                $controller = Controller::curr();
                if ($controller) {
                    if (!$this->ContextURL) {
                        // Store URL
                        $request = $controller->getRequest();
                        if ($request) {
                            $this->ContextURL = $request->getURL(true);
                        }
                    }

                    // Store PageID
                    if (!$this->ContextPageID) {
                        $page = null;
                        if ($controller instanceof ContentController) {
                            $page = $controller->data();
                        }
                        if ($controller instanceof LeftAndMain) {
                            $page = $controller->currentRecord();
                        }
                        if ($page && $page->exists()) {
                            $this->ContextPageID = $page->ID;
                        }
                    }
                }
            }
        }
    }

    public function onAfterWrite()
    {
        if ($this->FileID) {
            // Remove any older scan records on the same file
            // that are waiting to scan.
            // ie. ClamAVScanTask finds 'IsScanned => 0' items then
            // creates a new scan record. If this happens, remove
            // any "pending to be scanned" records (ie. IsScanned = 0)
            $oldScanRecords = self::get()->filter([
                'FileID' => $this->FileID,
                'IsScanned' => 0,
                'Action' => ClamAVScan::ACTION_NONE,
                'ID:not' => $this->ID,
            ]);
            foreach ($oldScanRecords as $record) {
                $record->delete();
            }
        }
        // Queue the job (if needed)
        if (!$this->IsScanned && class_exists(ClamAVScanJob::class)) {
            Injector::inst()->get(ClamAVScanJob::class)->queueMyselfIfNeeded();
        }
    }

    /**
     * Scan/Re-scan the item.
     */
    public function processFileActionScan(): bool
    {
        $file = $this->File();
        if (!$file || !$file->exists()) {
            return false;
        }
        $clamAVScan = $file->scanForVirus();
        if (!$clamAVScan) {
            return false;
        }
        $member = Security::getCurrentUser();

        if ($member) {
            $clamAVScan->ActionMemberID = $member->ID;
        }

        $clamAVScan->write();

        return true;
    }

    /**
     * Change state of scanned item to say file is deleted.
     *
     * @throws ValidationException
     */
    public function processFileActionDelete(): bool
    {
        if ($this->FileID > 0) {
            /** @var File $file */
            $file = $this->File();
            if ($file->exists()) {
                $file->deleteFile();
            }
        }
        $action = (int)$this->Action;
        if ($action !== ClamAVScan::ACTION_DELETED) {
            $this->Action = ClamAVScan::ACTION_DELETED;
            $member = Security::getCurrentUser();

            if ($member) {
                $this->ActionMemberID = $member->ID;
            }

            $this->write();

            return true;
        }

        return false;
    }

    /**
     * Change state of scanned item to say file is deleted.
     *
     * @throws ValidationException
     */
    public function processFileActionIgnore(): bool
    {
        $action = (int)$this->Action;
        if ($action !== ClamAVScan::ACTION_IGNORED) {
            $this->Action = ClamAVScan::ACTION_IGNORED;
            $member = Security::getCurrentUser();

            if ($member) {
                $this->ActionMemberID = $member->ID;
            }
            $this->write();

            return true;
        }

        return false;
    }

    public function getState(): int
    {
        $action = $this->Action;
        if ($action != self::ACTION_NONE) {
            switch ($action) {
                case self::ACTION_DELETED:
                    if ($this->IsInfected) {
                        return self::STATE_DELETED_INFECTED;
                    }
                    if ($this->IsScanned) {
                        return self::STATE_DELETED_CLEAN;
                    }

                    return self::STATE_DELETED_UNSCANNED;

                    break;

                case self::ACTION_IGNORED:
                    if ($this->IsInfected) {
                        return self::STATE_IGNORED_INFECTED;
                    }

                    return self::STATE_IGNORED_UNSCANNED;

                    break;

                default:
                    throw new LogicException('Invalid state (' . $action . ')');

                    break;
            }
        }
        if ($this->IsScanned) {
            return ($this->IsInfected) ? self::STATE_INFECTED : self::STATE_CLEAN;
        }

        return self::STATE_UNSCANNED;
    }

    public function getLocationUploaded(): null|DBHTMLText|string
    {
        // $getVars = explode('?', $this->ContextURL);
        // $getVars = isset($getVar[1]) ? '?'.$getVar[1] : '';

        $link = $this->ContextURL;
        $page = $this->ContextPage();
        if ($page && $page->exists() && $page->canEdit()) {
            $link .= ' <a href="' . $page->getCMSEditLink() . '">(Edit #' . $page->ID . ')</a>';
            $html = new DBHTMLText('URLLink');
            $html->setValue($link);

            return $html;
        }

        return $link;
    }

    /**
     * @throws LogicException
     */
    public function getStateMessage(): DBHTMLText
    {
        $colour = '#C00';
        $text = '';

        $action = $this->State;
        $state_messages = $this->config()->state_messages;
        if (!isset($state_messages[$action])) {
            $action = self::STATE_INVALID;
        }
        if (isset($state_messages[$action])) {
            $actionData = $state_messages[$action];

            switch ($actionData['type']) {
                case 'bad':
                    $colour = '#C00';

                    break;

                case 'warning':
                    $colour = '#1391DF';

                    break;

                case 'good':
                    $colour = '#18BA18';

                    break;

                default:
                    throw new LogicException('Invalid type "' . $actionData['type'] . '".');

                    break;
            }
            $text = $actionData['message'];
        }
        $html = new DBHTMLText('ActionMessage');
        $html->setValue(sprintf(
            '<span style="color: %s;">%s</span>',
            $colour,
            htmlentities($text)
        ));

        return $html;
    }

    public function getUserIdentifier(): ?string
    {
        if ($this->MemberID) {
            $member = $this->Member();

            return $member->Email . ' #' . $member->ID . ' (' . $this->IPAddress . ')';
        }

        return $this->IPAddress;
    }

    public function getRawDataSummary(): ?string
    {
        $rawData = $this->RawData;

        return ($rawData && isset($rawData['status'])) ? $rawData['status'] : '';
    }

    public function getRawData(): array
    {
        $value = $this->getField('RawData');
        if (is_string($value)) {
            $value = json_decode($value, true);
        }

        return (array)$value;
    }

    /**
     * @throws JsonException
     */
    public function setRawData(mixed $value): void
    {
        if (is_array($value)) {
            $value = json_encode($value, JSON_THROW_ON_ERROR);
        }
        $this->setField('RawData', $value);
    }

    /**
     * {@inheritdoc}
     */
    public function canEdit($member = null)
    {
        $extended = $this->extendedCan(__FUNCTION__, $member);
        if ($extended !== null) {
            return $extended;
        }

        return false;
    }

    /**
     * {@inheritdoc}
     */
    public function canDelete($member = null)
    {
        $extended = $this->extendedCan(__FUNCTION__, $member);
        if ($extended !== null) {
            return $extended;
        }

        return false;
    }
}
