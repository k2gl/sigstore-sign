<?php

declare(strict_types=1);

namespace K2gl\SigstoreSign\Exception;

use RuntimeException;

/** Fulcio (or the OIDC credential step) did not yield a usable signing certificate. */
final class FulcioException extends RuntimeException implements SigstoreSignException {}
