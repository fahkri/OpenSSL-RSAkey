# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test;
BEGIN { plan tests => 2 };
use OpenSSL::RSAkey;

if('da39a3ee5e6b4b0d3255bfef95601890afd80709' eq unpack("H*",OpenSSL::RSAkey::sha1(''))) {
   ok(1);
}else{
   ok(0);
}
if('3b71f43ff30f4b15b5cd85dd9e95ebc7e84eb5a3' eq unpack("H*", OpenSSL::RSAkey::sha1("\x{0}" x (1024*1024)))) {
   ok(1);
}else{
   ok(0);
}
