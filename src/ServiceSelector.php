<?php

declare(strict_types=1);

namespace K2gl\SigstoreSign;

/**
 * How many services of a kind a client should use, as the signing config asks.
 * The values are the enum names sigstore's protobuf-specs uses in JSON.
 */
enum ServiceSelector: string
{
    /** Every service that meets the criteria. */
    case All = 'ALL';

    /** One service; which one is the client's choice. */
    case Any = 'ANY';

    /** Exactly `count` services, each from a distinct operator. */
    case Exact = 'EXACT';
}
