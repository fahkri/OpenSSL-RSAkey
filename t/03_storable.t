# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test;
BEGIN { plan tests => 1 };
use OpenSSL::RSAkey;
use Storable qw(thaw freeze);

$key = new OpenSSL::RSAkey(128);

$serialized = freeze($key);
$cloned = thaw($serialized);

if($key->n eq $cloned->n
      && $key->e eq $cloned->e
      && $key->p eq $cloned->p
      && $key->q eq $cloned->q
      && $key->d eq $cloned->d
      && $key->iqmp eq $cloned->iqmp
      && $key->dmp1 eq $cloned->dmp1
      && $key->dmq1 eq $cloned->dmq1) {
	ok(1);
} else {
   ok(0);
}
	

