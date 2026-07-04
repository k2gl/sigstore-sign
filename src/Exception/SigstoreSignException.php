<?php

declare(strict_types=1);

namespace K2gl\SigstoreSign\Exception;

use Throwable;

/**
 * Marker for every exception this package throws, so callers can catch the whole
 * family with one type.
 */
interface SigstoreSignException extends Throwable {}
