use strict;
use warnings;
use Test2::V0;

plan(1);

like(`openssl list -provider nullcipher -cipher-algorithms`,
     qr/NULL @ nullcipher\n/,
     'NULL@nullcipher is listed');
