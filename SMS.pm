
use 5.006;
use strict;
use warnings;

package OpenSSL::RSAkey::SMS;
use OpenSSL::RSAkey;

sub new($;$) {
   my ($class, $msg) = @_;
   my $self = bless {}, $class;

   $self->{msg} = undef;
   $self->{signers} = [];
   $self->{key} = undef;
   $self->{dest} = [];
   $self->set_message($msg) if $msg;
   $self;
}

sub set_message($$) {
   my ($self, $msg) = @_;
   die "message already set" if $self->{msg};
   $self->{msg} = $msg;
}

sub set_key($$) {
   my ($self, $key) = @_;
   die "key already set" if $self->{key};
   $self->{key} = $key;
}

sub add_dests($@) {
   my ($self, @dests) = @_;
   for(@dests) {
      push @{$self->{dest}}, $_;
   }
}

sub add_signers($@) {
   my ($self, @si) = @_;
   for(@si) {
      die "signing only possible with private key" unless $_->{key}->is_privkey;
      push @{$self->{signers}}, $_;
   }
}

# currently disabled, does not work for now.
sub rnd16 {
   #OpenSSL::RSAkey::pseudorandombytes(16);
   "";
}
sub rnd_skip {
   0
}

sub final($) {
   my ($self) = shift;

   my $key = $self->{key};
   my $out = '';
   my $sha1_pad24 = undef;

   die "no message !" unless $self->{msg};
   
   $key = OpenSSL::RSAkey::randombytes(16) unless $key;

   # pack key-length (native)
   $out = pack("C", length($key));

 
   # encrypt the blowfish key and the key-fingerprint :)

   for my $k (@{$self->{dest}}) {
      my $fp = $k->{key}->fingerprint;
      my $klen = $k->{key}->keysize / 8;
      my $pkt = &rnd16 . $fp . $key;
      my $delta = $klen - length($pkt);
      die "key to long" if $delta < 0;
      $pkt .= ("x" x $delta) if $delta;
      my $sec = $k->{key}->public_encrypt($pkt);
      $out .= 'K' . pack('n', length($sec)) . $sec
   }

   #
   # attach message. (length is real message size, but encoding is padded
   # to 8 byte bondary
   #
   my $pkt = &rnd16 . $self->{msg};
   $pkt .= ("x" x (8 - (length($pkt) % 8))) if length($pkt) & 0x7;
   $out .= 'M' . pack('N', length($self->{msg}));
   $out .= OpenSSL::RSAkey::blowfish_encrypt($key, $pkt);
   #
   # We attach a checksum packet that is encrypted by the same key
   # its unencoded 24 bytes: sha1(unencrypted). "    "
   #
   $sha1_pad24 = OpenSSL::RSAkey::sha1($self->{msg}) . (" " x 4);
   $out .= 'T' . OpenSSL::RSAkey::blowfish_encrypt($key, $sha1_pad24);


   #
   # Signing. hmm. We perform crypto signing.
   # Only people that can decode the packet are allowed to
   # verify/see a signature.
   # the packet is rsa-size long.
   # we run blowfish over private_encrypt(rsa_fingerprint, sha1_pad24,
   #
   for my $k (@{$self->{signers}}) {
      my $ps = $k->{key}->keysize / 8; 
      my $pkt = &rnd16 . $k->{key}->fingerprint;
         $pkt .= $sha1_pad24;
         $pkt .= (" " x ($ps - length($pkt)));
      my $xpkt = $k->{key}->private_encrypt($pkt);
      $out .= 'S' . pack('n', $ps) . OpenSSL::RSAkey::blowfish_encrypt($key, $xpkt);
   }
   $out;
}

#
#  Extracter
#

sub extractmsg($@)
{
 my ($msg, @keys) = @_;
 my $keylen = unpack("C", $msg);
 my $secret = undef;
 my $crypt_message = undef;
 my $crypt_message_len = undef;
 my $crypt_checksum = undef;
 my @crypt_signers = ();
 my $self_checksum = undef;
 my @checked_signs = ();
 #print STDERR "keylength = $keylen\n";
 $msg = substr($msg, 1);
 
 while(length($msg)) {
    my $func = substr($msg, 0, 1);
    $msg = substr($msg,1);
    if($func eq 'K') {
          # key packet
          my $len = unpack('n', $msg);
          $msg = substr($msg, 2);
          #print STDERR "key-header ($len) found\n";
          my $ekey = substr($msg, 0, $len);
          $msg = substr($msg, $len);
          next if $secret; # skip header, we already have the key.
          # find matching key. extract must give fingerprint.
          for my $k (@keys) {
             next unless $k->{key}->is_privkey;
             next unless $k->{key}->keysize == ($len*8);
             #print STDERR "trying " .$k->{subject}."\n";
             my $try = $k->{key}->private_decrypt($ekey);
             my $fp = $k->{key}->fingerprint;
             if(substr($try, 0, length($fp)) eq $fp) {
                $secret = substr($try, length($fp), $keylen);
             }
             
          }
	next;
    }
    if($func eq 'M') {
       # real message
          my $len = unpack('N', $msg);
          my $elen = ($len + 7) & 0xfffffff8;
          $crypt_message = substr($msg, 4, $elen);
          $crypt_message_len = $len;
          $msg = substr($msg, 4+$elen);
          #print STDERR "msg-header ($len,$elen) found\n";
          next;
    }
    if($func eq 'T') {
       # checksum packet
       $crypt_checksum = substr($msg, 0, 24);
       $msg = substr($msg, 24);
       next;
    }
    if($func eq 'S') {
       # sign packet
       #print "msglen = " . length($msg) . "\n";
       my $len = unpack('n', $msg);
       push @crypt_signers, substr($msg, 2+&rnd_skip, $len-&rnd_skip);
       $msg = substr($msg, $len+2);
       next;
    }
       
    warn "Illegal or unsupported message '$func' or trailing junk finlen=".length($msg);
    last;
}
    ################################
    # we _should_ have:
    # $crypt_message     == encrypted message
    # $crypt_message_len == message length
    # $crypt_checksum    == sha1(unecrypted_msg) . (" " x 4)
    # $secret            == key.
    # @crypt_signers     == stupid people that sign. :)

    die "no message in stream" unless $crypt_message;
    die "none of our secret keys does fit" unless $secret;

    my $decrypted = OpenSSL::RSAkey::blowfish_decrypt($secret, $crypt_message);
    $decrypted = substr($decrypted, 0+&rnd_skip, $crypt_message_len-&rnd_skip); 
    $self_checksum = OpenSSL::RSAkey::sha1($decrypted).(" " x 4);
    my $checksum_valid = 0;
    if($crypt_checksum) {
    	my $dchecksum = OpenSSL::RSAkey::blowfish_decrypt($secret, $crypt_checksum);
        $checksum_valid = 1 if $self_checksum eq $dchecksum;
    }
    for my $s (@crypt_signers) {
       #print "debug: length(s)=".length($s)."\n";
       $s = OpenSSL::RSAkey::blowfish_decrypt($secret, $s);
       my $sl = length($s);
       for my $k (@keys) {
          next if $k->{key}->is_privkey;
          next unless $sl*8 == $k->{key}->keysize;
          my $t = $k->{key}->public_decrypt($s);
          my $fp = $k->{key}->fingerprint;
          next unless $fp eq substr($t, 0+&rnd_skip, length($fp)-&rnd_skip);
          push @checked_signs, $k if $self_checksum eq substr($t, length($fp), length($self_checksum));
       }
    }
    ($decrypted, $checksum_valid, \@checked_signs);
}

1;
__END__

=head1 NAME

OpenSSL::RSAkey::SMS - Secure Message System

=head1 SYNOPSIS

#!/usr/bin/perl

use OpenSSL::RSAkey::SMS;
use OpenSSL::RSAkey::XMLKeys;

my $ring = new OpenSSL::RSAkey::XMLKeys;

$ring->addkeys('minirsa.xml');

my $sms = new OpenSSL::RSAkey::SMS('hallo du sepp');

$sms->add_dests($ring->pubkey_by_email('pcg@goof.com'),
      		$ring->pubkey_by_subject('Stefan Traby'));
$sms->add_signers($ring->privkey_by_subject('Stefan Traby'));

my $secret = $sms->final;

my ($decrypted, $chksumok, $sigs) =  OpenSSL::RSAkey::SMS::extractmsg($secret, ($ring->all_pubkeys, $ring->all_privkeys));

print "msg was: $decrypted\nchecksumok=$chksumok\n";
print "signed by ".$_->{subject}."\n" for ($sigs);
  
=head1 DESCRIPTION

Complete RSA system with blowfish encoding and sha1 digest and XML Keysupport?? :)

=head2 EXPORTS

None by default.

=head2 BUGS

None by default.
People want private keys in XML encrypted. I don't want that.
Store XML-File on a loop-mounted crypto filesystem :)

=head1 AUTHORS

Stefan Traby <oesi@plan9.de>

=head1 SEE ALSO

L<perl>.

=cut
