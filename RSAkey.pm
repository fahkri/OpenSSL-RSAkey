package OpenSSL::RSAkey;

use 5.006;
use strict;
use warnings;

our $VERSION = '0.05';

require XSLoader;

#XSLoader::load OpenSSL::RSAkey, $VERSION;
XSLoader::load OpenSSL::RSAkey;

1;
__END__

=head1 NAME

OpenSSL::RSAkey - Perl extension to generate and use RSA keys using the openssl library

=head1 SYNOPSIS

  use OpenSSL::RSAkey;

  my $key = new OpenSSL::RSAkey [keysize [,e]] ;
  print $key->n;
  print $key->e;
  print $key->d;
  print $key->q;
  print $key->p;
  print $key->dmp1;
  print $key->dmq1;
  print $key->iqmp;
  print $key->keysize;
  print unpack("H*", $key->fingerprint); # SHA1 fingerprint.

  additionally it is possible to load prebuild keys:

  my $pubkey = new_pubkey OpenSSL::RSAkey(n, e);
  my $privkey = new_privkey OpenSSL::RSAkey(n,e,p,q,dmp1,dmq1,iqmp,d);

  my $enc = $pubkey->encrypt("key-sized text");
  my $dec = $privkey->decrypt($enc);
  
  
  
=head1 DESCRIPTION

OpenSSL::RSAkey generates RSA keys.

=head2 EXPORTS

None by default.

=head2 BUGS

None by default.

=head1 AUTHORS

Stefan Traby <oesi@plan9.de>
Marc Lehmann <pcg@goof.com>

=head1 SEE ALSO

L<perl>.

=cut
