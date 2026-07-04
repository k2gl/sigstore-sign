<?php

declare(strict_types=1);

namespace K2gl\SigstoreSign\Exception;

use RuntimeException;

/** Something in the signing flow went wrong (a signature, a Rekor submission, a timestamp). */
final class SigningException extends RuntimeException implements SigstoreSignException {}
