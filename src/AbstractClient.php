<?php
declare(strict_types=1);
namespace FediE2EE\PKD;

use FediE2EE\PKD\Crypto\PublicKey;

abstract class AbstractClient
{
    protected string $url;
    protected PublicKey $pk;

}
