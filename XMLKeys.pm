
use 5.006;
use strict;
use warnings;

package OpenSSL::RSAkey::XMLKeys;
use OpenSSL::RSAkey;
use XML::Parser;

sub new($) {
   my $class = shift;
   my $self = bless {}, $class;

   $self->{pubkeys} = [];
   $self->{privkeys} = [];
   $self;
}

sub addkeys($$) {
   my ($self, $fn) = @_;
   my ($sub, $email);

   my $p = new XML::Parser;
   
   $p->setHandlers(Start => sub {
       my ($ex, $el, %a) = @_;
       if($el eq 'key') {
       		$sub = $a{subject};
        	$email = $a{email};
       }
       return unless defined($sub) && defined($email);
       if($el eq 'rsapubkey') {
       	my $k = new_pubkey OpenSSL::RSAkey($a{n}, $a{e});
        my %set = (key => $k, email => $email, subject => $sub);
        push @{$self->{pubkeys}}, \%set;
       }
       if($el eq 'rsaprivkey') {
         my $k;
         eval {
          $k = new_privkey OpenSSL::RSAkey($a{n}, $a{e}, $a{p}, $a{q},
         				  $a{dmp1}, $a{dmq1}, $a{iqmp}, $a{d});
         };
         my %set = (key => $k, email => $email, subject => $sub);
         push @{$self->{privkeys}}, \%set;
        }
       });
 $p->setHandlers(End => sub {
       my ($ex, $el, %attr) = @_;
       if($el eq 'key') {
       		undef $sub;
                undef $email;
       }
       });
       
  $p->parsefile($fn);
}
   
sub pubkey_by_email($$)
{
 my ($self, $email) = @_;
 my $ret = undef;

 for(@{$self->{pubkeys}}) {
    if($_->{email} =~ $email) {
       # dupes
       return undef if $ret;
       $ret = $_;
    }
 }
 return $ret;
}

sub all_pubkeys($)
{
 @{$_[0]->{pubkeys}};
}

sub pubkey_by_subject($$)
{
 my ($self, $sub) = @_;
 my $ret = undef;

 for(@{$self->{pubkeys}}) {
    if($_->{subject} =~ $sub) {
       # dupes
       return undef if $ret;
       $ret = $_;
    }
 }
 return $ret;
}


sub privkey_by_email($$)
{
 my ($self, $email) = @_;
 my $ret = undef;

 for(@{$self->{privkeys}}) {
    if($_->{email} =~ $email) {
       # dupes
       return undef if $ret;
       $ret = $_;
    }
 }
 return $ret;
}

sub all_privkeys($)
{
 @{$_[0]->{privkeys}};
}

sub privkey_by_subject($$)
{
 my ($self, $sub) = @_;
 my $ret = undef;

 for(@{$self->{privkeys}}) {
    if($_->{subject} =~ $sub) {
       # dupes
       return undef if $ret;
       $ret = $_;
    }
 }
 return $ret;
}



1;
__END__

=head1 NAME

OpenSSL::RSAkey::XMLKeys - Simple RSA-Key management.

=head1 SYNOPSIS

  
=head1 DESCRIPTION


=head2 EXPORTS

None by default.

=head2 BUGS

None by default.

=head1 AUTHORS

Stefan Traby <oesi@plan9.de>

=head1 SEE ALSO

L<perl>.

=cut
