<?php

declare(strict_types=1);

namespace K2gl\SigstoreSign\Exception;

use RuntimeException;

/** The timestamp authority did not return a usable RFC 3161 token. */
final class TimestampException extends RuntimeException implements SigstoreSignException {}
