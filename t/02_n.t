# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test;
use Math::BigInt;
BEGIN { plan tests => 1 };
use OpenSSL::RSAkey;

$k = new OpenSSL::RSAkey(256);

$p = new Math::BigInt($k->p);
$q = new Math::BigInt($k->q);
$n = new Math::BigInt($k->n);
$nn = $p * $q;

if ($n != $nn) {
   print STDERR "oops, expected: $nn\ngot: $n\n";
   ok(0);
} else { 
   ok(1);
}

