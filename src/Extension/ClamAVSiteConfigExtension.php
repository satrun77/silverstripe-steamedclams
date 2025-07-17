<?php

namespace Symbiote\SteamedClams\Extension;

use SilverStripe\Core\Extension;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\TextField;

/**
 * This extension adds contact information such as 'Phone' and 'Email' as well
 * as 'SocialMediaLinks'.
 */
class ClamAVSiteConfigExtension extends Extension
{
    private static array $db = [
        'ValidationMessage' => 'Varchar(255)',
    ];

    private static array $defaults = [
        'validationMessage' => 'A virus was detected.',
    ];

    public function updateCMSFields(FieldList $fields): void
    {
        $fields->addFieldsToTab(
            'Root.ClamAV',
            [
                TextField::create('ValidationMessage', 'Validation Message')
                    ->setDescription('This will display as a validation message when virus detected.'),
            ]
        );
    }
}
