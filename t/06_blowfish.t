# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test;
BEGIN { plan tests => 2 };
use OpenSSL::RSAkey;

$key = "paul ist vaul";
$clear = "x" x 1024;

my $enc = OpenSSL::RSAkey::blowfish_encrypt($key, $clear);
my $dec = OpenSSL::RSAkey::blowfish_decrypt($key, $enc);

if($clear eq $dec && $dec ne $enc) {
   ok(1);
} else {
   ok(0);
}

# text must be a multiple of 64 bit long

eval {OpenSSL::RSAkey::blowfish_encrypt($key, "x" x 7)};
if($@ =~ /^illegal/) {
   ok(1);
}else{
   ok(0);
}

