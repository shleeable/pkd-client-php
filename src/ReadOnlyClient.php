<?php
declare(strict_types=1);
namespace FediE2EE\PKD;

use FediE2EE\PKD\Crypto\PublicKey;
use FediE2EE\PKD\Features\FetchTrait;

/**
 * A client for fetching data from the Public Key Directory, and not writing.
 * @api
 */
final class ReadOnlyClient extends AbstractClient
{
    use FetchTrait;

    public function __construct(
        string $url,
        PublicKey $pk
    ) {
        $this->url = $url;
        $this->pk = $pk;
    }
}
