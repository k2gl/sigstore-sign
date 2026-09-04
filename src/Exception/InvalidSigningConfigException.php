<?php

declare(strict_types=1);

namespace K2gl\SigstoreSign\Exception;

use RuntimeException;

/** The signing config is malformed, or it holds no service that meets the selection criteria. */
final class InvalidSigningConfigException extends RuntimeException implements SigstoreSignException {}
