<?php
declare(strict_types=1);
namespace FediE2EE\PKD;

use FediE2EE\PKD\Crypto\PublicKey;
use FediE2EE\PKD\Crypto\SecretKey;
use FediE2EE\PKD\Extensions\Registry;
use FediE2EE\PKD\Features\FetchTrait;
use FediE2EE\PKD\Features\PublishTrait;

/**
 * A fully-featured client for the Public Key Directory. Reads and writes.
 * @api
 */
final class Client extends AbstractClient
{
    use FetchTrait;
    use PublishTrait;

    protected ?SecretKey $sk = null;

    public function __construct(
        string $url,
        PublicKey $pk,
        Registry $registry = null,
        ?SecretKey $sk = null,
    ) {
        $this->url = $url;
        $this->pk = $pk;
        $this->sk = $sk;
        if (is_null($registry)) {
            $registry = new Registry();
        }
        $this->registry = $registry;
    }
}
