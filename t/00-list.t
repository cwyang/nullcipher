use strict;
use warnings;
use Test2::V0;

plan(4);

like(`openssl list -provider nullcipher -cipher-algorithms`,
     qr/NULL @ nullcipher\n/,
     'NULL@nullcipher is listed');

like(`openssl list -provider ariacipher -cipher-algorithms`,
     qr/ARIA256 \} @ ariacipher\n/,
     'ARIA256@ariacipher is listed');
like(`openssl list -provider ariacipher -cipher-algorithms`,
     qr/ARIA192 \} @ ariacipher\n/,
     'ARIA192@ariacipher is listed');
like(`openssl list -provider ariacipher -cipher-algorithms`,
     qr/ARIA128 \} @ ariacipher\n/,
     'ARIA128@ariacipher is listed');
