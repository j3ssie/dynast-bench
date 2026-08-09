<?php

namespace App\Support;

// DESER-001 gadget. A "backup descriptor" whose destructor writes a file to
// disk — exactly the kind of magic-method side effect that turns a call to
// unserialize() on attacker input into arbitrary file write / RCE. It looks
// innocuous (a legit backup helper) which is why it survives review.
class Backup
{
    public string $path = '';
    public string $contents = '';

    public function __destruct()
    {
        if ($this->path !== '') {
            @file_put_contents($this->path, $this->contents);
        }
    }
}
