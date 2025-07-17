<?php

namespace Symbiote\SteamedClams\Tasks\Traits;

use Exception;
use Psr\Log\LoggerInterface;
use SilverStripe\Core\Convert;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\DB;

trait LogTrait
{
    /**
     * Custom error handler so that 'user_error' underneath the 'log' function just prints
     * like everything else.
     */
    public function log_error_handler(int $errno, string $errstr, ?string $errfile = null, ?int $errline = null, ?array $errcontext = null): void
    {
        DB::alteration_message($errstr, 'error');

        // Send out the error details to the logger for writing
        $error = [
            'errno' => $errno,
            'errstr' => $errstr,
            'errfile' => $errfile,
            'errline' => $errline,
            'errcontext' => $errcontext,
        ];
        Injector::inst()->get(LoggerInterface::class)
            ->error('Query executed: ' . implode(',', $error));
    }

    protected function log(DataObject|string $messageOrDataObject, string $type = '', ?Exception $exception = null, int $indent = 0)
    {
        $message = '';
        for ($i = 0; $i < $indent; ++$i) {
            $message .= '--';
        }
        if ($message) {
            $message .= ' ';
        }

        if (is_object($messageOrDataObject)) {
            $record = $messageOrDataObject;

            switch ($type) {
                case 'created':
                    $message .= 'Added "' . $record->Title . '" (' . $record->class . ') to #' . $record->ID;

                    break;

                case 'error':
                    $message .= 'Failed to write #' . $record->ID;

                    break;

                case 'changed':
                case 'notice':
                    $message .= 'Changed "' . $record->Title . '" (' . $record->class . ') #' . $record->ID;

                    break;

                case 'deleted':
                    $message = 'Deleted "' . $record->Title . '" (' . $record->class . ') #' . $record->ID;
                    $type = 'created';

                    break;

                // Special Cases for $record
                case 'published':
                    $message .= 'Published "' . $record->Title . '" (' . $record->class . ') #' . $record->ID;
                    $type = 'changed';

                    break;

                case 'unpublished':
                    $message .= 'Unpublished "' . $record->Title . '" (' . $record->class . ') #' . $record->ID;
                    $type = 'changed';

                    break;

                case 'archive':
                    $message .= 'Archive "' . $record->Title . '" (' . $record->class . ') #' . $record->ID;
                    $type = 'changed';

                    break;

                case 'delete_error':
                    $message = 'Unable to delete "' . $record->Title . '" (' . $record->class . ') #' . $record->ID;
                    $type = 'error';

                    break;

                case 'unpublished_error':
                    $message .= 'Unable to unpublish "' . $record->Title . '" (' . $record->class . ') #' . $record->ID;
                    $type = 'error';

                    break;

                case 'archive_error':
                    $message .= 'Unable to archive "' . $record->Title . '" (' . $record->class . ') #' . $record->ID;
                    $type = 'error';

                    break;

                case 'nochange':
                    $message = 'No changes to "' . $record->Title . '" (' . $record->class . ') #' . $record->ID;
                    $type = '';

                    break;

                default:
                    throw new Exception('Invalid log type ("' . $type . '") passed with $record.');

                    break;
            }
        } else {
            $message .= $messageOrDataObject;
        }
        if ($exception) {
            $message .= ' -- ' . $exception->getMessage() . ' -- File: '
                . basename($exception->getFile()) . ' -- Line ' . $exception->getLine();
        }

        switch ($type) {
            case '':
                DB::alteration_message(Convert::raw2xml($message));

                break;

            case 'created':
                DB::alteration_message(Convert::raw2xml($message), 'created');

                break;

            case 'error':
                set_error_handler([$this, 'log_error_handler']);
                user_error($message, E_USER_WARNING);
                restore_error_handler();

                break;

            case 'changed':
                DB::alteration_message(Convert::raw2xml($message), 'changed');

                break;

            case 'notice':
            case 'warning':
                DB::alteration_message(Convert::raw2xml($message), 'notice');

                break;

            default:
                throw new Exception('Invalid log $type (' . $type . ') passed.');

                break;
        }
    }
}
