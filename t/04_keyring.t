# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test;
BEGIN { plan tests => 1 };
use OpenSSL::RSAkey;
use OpenSSL::RSAkey::XMLKeys;
	
my $ring = new OpenSSL::RSAkey::XMLKeys;

   $ring->addkeys('./minirsa.xml');

   if($ring->pubkey_by_email('pcg@goof.com')
      && $ring->privkey_by_subject('Stefan Traby')) {
      ok(1);
   } else {
      ok(0);
   }


