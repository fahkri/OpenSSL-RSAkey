# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test;
BEGIN { plan tests => 1 };
use OpenSSL::RSAkey;
use OpenSSL::RSAkey::XMLKeys;
use OpenSSL::RSAkey::SMS;
	
my $ring = new OpenSSL::RSAkey::XMLKeys;

$ring->addkeys('./minirsa.xml');

$broken_locale = "Hildesheim/Niedersachsen/Germany";

# message from Stefan to Marc...

$msg = new OpenSSL::RSAkey::SMS;
$msg->set_message($broken_locale);
$msg->add_dests($ring->pubkey_by_email('pcg@goof.com'));
$msg->add_signers($ring->privkey_by_subject('Stefan Traby'));
$enc = $msg->final;

# let's see what Marc gets:

($decrypted, $chksumok, $signers) = OpenSSL::RSAkey::SMS::extractmsg($enc,($ring->all_pubkeys, $ring->all_privkeys));

if($decrypted eq $broken_locale
   && $chksumok
   && $$signers[0]->{subject} eq 'Stefan Traby') {
	ok(1);
}else {
        ok(0);
}
