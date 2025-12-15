<?php
declare(strict_types=1);
namespace FediE2EE\PKD;

use FediE2EE\PKD\Crypto\PublicKey;
use FediE2EE\PKD\Extensions\Registry;

abstract class AbstractClient
{
    protected string $url;
    protected PublicKey $pk;
    protected Registry $registry;
}
