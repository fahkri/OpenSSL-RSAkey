# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test;
BEGIN { plan tests => 3 };
use OpenSSL::RSAkey;
ok(1); # If we made it this far, we're ok.

#########################

# Insert your test code below, the Test module is use()ed here so read
# its man page ( perldoc Test ) for help writing this test script.

$x = new OpenSSL::RSAkey;
# default keysize: 128
if ($x->keysize != 128) {
    print STDERR "invalid keysize: " . $x->keysize . "\n";
    ok(0);
} else {
   ok(1);
}
   
$y = new OpenSSL::RSAkey(256);
die "key verification failed" unless $y->check_key;
$y = undef;
ok(1);


