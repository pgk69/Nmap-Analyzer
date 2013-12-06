package NMAPANALYZE;

#-------------------------------------------------------------------------------------------------
# Letzte Aenderung:     $Date:  $
#                       $Revision:  $
#                       $Author:  $
#
# Aufgabe:				- Ausfuehrbarer Code von nmapanalyze.pl
#
# $Id:  $
# $URL:  $
#-------------------------------------------------------------------------------------------------

use 5.004;
use strict;
use vars qw($VERSION $SVN $OVERSION);

use constant SVN_ID => '($Id:  $)

$Author:  $ 

$Revision:  $ 
$Date:  $ 

$URL:  $

';

($VERSION = SVN_ID) =~ s/^(.*\$Revision: )([0-9]*)(.*)$/1.0 R$2/ms;
$SVN      = $VERSION . ' ' . SVN_ID;
$OVERSION = $VERSION;

use base 'Exporter';

our @EXPORT    = ();
our @EXPORT_OK = ();

use vars @EXPORT, @EXPORT_OK;

use vars qw(@ISA);
@ISA = qw();

use Trace;
use CmdLine;
use Configuration;
use DBAccess;

#
# Module
#
use Utils;
use FindBin qw($Bin $Script $RealBin $RealScript);
use Date::Format;
use File::Basename;
use File::Path qw(mkpath);
use MIME::Lite;
use IO::Compress::Gzip qw(gzip $GzipError);
use LockFile::Simple qw(lock trylock unlock);
use Data::Dumper;

#
# Konstantendefinition
#

#
# Variablendefinition
#

#
# Methodendefinition
#

sub version {
  my $self     = shift();
  my $pversion = shift();

  $OVERSION =~ m/^([^\s]*)\sR([0-9]*)$/;
  my ($oVer, $oRel) = ($1, $2);
  $oVer = 1 if (!$oVer);
  $oRel = 0 if (!$oRel);

  if (defined($pversion)) {
    $pversion =~ m/^([^\s]*)\sR([0-9]*)$/;
    my ($pVer, $pRel) = ($1, $2);
    $pVer = 1 if (!$pVer);
    $pRel = 0 if (!$pRel);
    $VERSION = $oRel gt $pRel ? "$pVer R$oRel" : "$pVer R$pRel";
  }

  return wantarray() ? ($VERSION, $OVERSION) : $VERSION;
}


sub new {
  #################################################################
  #     Legt ein neues Objekt an
  my $self  = shift;
  my $class = ref($self) || $self;
  my @args  = @_;

  my $ptr = {};
  bless $ptr, $class;
  $ptr->_init(@args);

  return $ptr;
}


sub _init {
  #################################################################
  #   Initialisiert ein neues Objekt
  my $self = shift;
  my @args = @_;

  $self->{Startzeit} = time();
  
  $VERSION = $self->version(shift(@args));
 
  Trace->Trc('S', 1, 0x00001, Configuration->prg, $VERSION . " (" . $$ . ")" . " Test: " . Trace->test() . " Parameter: " . CmdLine->new()->{ArgStrgRAW});
  
  if (Configuration->config('Prg', 'Plugin')) {

    # refs ausschalten wg. dyn. Proceduren
    no strict 'refs';
    my %plugin = ();

    # Bearbeiten aller Erweiterungsmodule die in der INI-Date
    # in Sektion [Prg] unter "Plugin =" definiert sind
    foreach (split(/ /, Configuration->config('Prg', 'Plugin'))) {

      # Falls ein Modul existiert
      if (-e "$self->{Pfad}/plugins/${_}.pm") {

        # Einbinden des Moduls
        require $_ . '.pm';
        $_->import();

        # Initialisieren des Moduls, falls es eine eigene Sektion
        # [<Modulname>] fuer das Module in der INI-Datei gibt
        $plugin{$_} = eval {$_->new(Configuration->config('Plugin ' . $_))};
        eval {
          $plugin{$_} ? $plugin{$_}->DESTROY : ($_ . '::DESTROY')->()
            if (CmdLine->option('erase'));
        };
      }
    }
    use strict;
  }

  # Module::Refresh->refresh;
  
  # Lockfile
  if (Configuration->config('Prg', 'LockFile')) {
    $self->{LockFile} = File::Spec->canonpath(Utils::extendString(Configuration->config('Prg', 'LockFile'), "BIN|$Bin|SCRIPT|" . uc($Script)));
    $self->{Lock} = LockFile::Simple->make(-max => 5, -delay => 1, -format => '%f', -autoclean => 1, -stale => 1, -wfunc => undef);
    my $errtxt;
    $SIG{'__WARN__'} = sub {$errtxt = $_[0]};
    my $lockerg = $self->{Lock}->trylock($self->{LockFile});
    undef($SIG{'__WARN__'});
    if (defined($errtxt)) {
      $errtxt =~ s/^(.*) .+ .+ line [0-9]+.*$/$1/;
      chomp($errtxt);
      Trace->Trc('S', 1, 0x00012, $errtxt) if defined($errtxt);
    }
    if (!$lockerg) {
      Trace->Exit(0, 1, 0x00013, Configuration->prg, $self->{LockFile})
    } else {
      Trace->Trc('S', 1, 0x00014, $self->{LockFile})
    }
  }
  $self->{AutoCommit} = Configuration->config('DB', 'AUTOCOMMIT') || 0;

  # Ausgabeverzeichnisse
  if (Configuration->config('IO', 'Ausgabedatei')) {
    my $tmp = File::Spec->canonpath(Utils::extendString(Configuration->config('IO', 'Ausgabedatei')));
    if (Utils::mk_dir($tmp)) {
      Trace->Exit(0x103, 0, dirname($tmp), $@);
    }
    $self->{Ausgabedatei} = $tmp;
  }
  if (Configuration->config('IO', 'Certverzeichnis')) {
    my $tmp  = File::Spec->canonpath(Utils::extendString(Configuration->config('IO', 'Certverzeichnis') . "/dummy"));
     if (Utils::mk_dir($tmp)) {
      Trace->Exit(0x104, 0, dirname(File::Spec->canonpath(Utils::extendString(Configuration->config('IO', 'Certverzeichnis')))), $@);
    }
    $self->{Certdir}      = File::Spec->canonpath(Utils::extendString(Configuration->config('IO', 'Certverzeichnis')));
  }

  # DB-Zugriff
  if (Configuration->config('DB', 'RDBMS')) {
    my $stmt = 'INSERT INTO ' . Configuration->config('DB', 'DB') . ' (Date, Region, Host_IP, Hostname, HTML_Title, SubjectCN, IssuerCN, Selfsigned, CertKeyType, KeyBits, CertSHA1, CertPEM, ValidFrom, ValidTo, WeakCipherSuite, SSLv1, SSLv2, SSLv3, TLSv10, TLSv11, TLSv12, CipherSet) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)';
    DBAccess->prepare($stmt) or Trace->Exit(0x100, 0, "Error: $DBI::errstr");
  }
}


sub DESTROY {
  #################################################################
  #     Zerstoert das Objekt an
  my $self = shift;
  my ($rc, $sig) = (0,0);
  $rc  = ($? >> 8);
  $sig = $? & 127;
  if ($@ || $rc != 0 || $sig != 0) {
    my ( $routine, $i ) = ( ( caller(0) )[3] . ':', 0 );
    while ( defined( caller( ++$i ) ) ) {
      $routine .= ( caller($i) )[3] . '(' . ( caller( $i - 1 ) )[2] . '):';
    }
    Trace->Trc('S', 1, 0x00007, "$routine $@ $! $?");
    Trace->Log('Log', 0x10013, $@, $!, $?);
  }
  for my $parent (@ISA) {
    if ( my $coderef = $self->can( $parent . "::DESTROY" ) ) {
      $self->$coderef();
    }
  }
  # Eigentlich nicht noetig, da -autoclean => 1
  if ($self->{Lock}) {$self->{Lock}->unlock($self->{LockFile})}
}


sub lese_Fileliste {
  my $self = shift;
  
  my $eingabe           = File::Spec->canonpath(Utils::extendString(Configuration->config('IO', 'Eingabeverzeichnis')));
  $self->{fileList}     = Utils::fetchFileList($eingabe);
}


sub nextFile {
  my $self = shift;
  my @args = @_;
  
  my $rc = shift(@{$self->{fileList}});
  
  return $rc;
}


sub getInfo() {
  my $self   = shift;
  my $type   = shift;
  my $object = shift;

  undef($self->{Info}->{$type});
  my %args = Configuration->config('NMAP');
  foreach (keys %args) {
    if ($_ =~ m/^${type}\s+([^\s]+)$/) {
      $self->{Info}->{$type}->{$args{$_}} = join(' ', $object->$1) if $args{$_};
    }
  }
  
  return 0;;
}
  

sub analyseThis () {
  my $self    = shift;
  my $service = shift;

  my %info;
  foreach ('Selfsigned', 'WeakCipherSuite', 'SSLv1', 'SSLv2', 'SSLv3', 'TLSv10', 'TLSv11', 'TLSv12') {$info{$_} = 0}
  foreach my $script (keys($service->{script})) {
    my $content = $service->scripts($script)->{contents};
    my $output  = $service->scripts($script)->{output};
    
    if ($script eq "html-title-db") {
      $info{HTML_Title} = $output;
    } elsif ($script eq "my-ssl-cert") {
      foreach (keys(%$content)) {
        my $item = $content->{$_};
        if (($_ eq 'subject')  && defined($item->{commonName})) {$info{SubjectCN}   = $item->{commonName}}
        if (($_ eq 'issuer')   && defined($item->{commonName})) {$info{IssuerCN}    = $item->{commonName}}
        if (($_ eq 'pubkey')   && defined($item->{type}))       {$info{CertKeyType} = $item->{type}}
        if (($_ eq 'pubkey')   && defined($item->{bits}))       {$info{KeyBits}     = $item->{bits}}
        if (($_ eq 'validity') && defined($item->{notBefore}))  {($info{ValidFrom}  = $item->{notBefore}) =~ s/T|\+.*/ /g}
        if (($_ eq 'validity') && defined($item->{notAfter}))   {($info{ValidTo}    = $item->{notAfter})  =~ s/T|\+.*/ /g}
        if  ($_ eq 'pem')                                       {$info{CertPEM}     = $item}
        if  ($_ eq 'sha1')                                      {$info{CertSHA1}    = $item}
      }
    } elsif ($script eq "my-ssl-enum-ciphers") {
      $info{CipherSet} = $output;
      my %cipher;
      foreach my $secType (keys(%$content)) {
        my $item = $content->{$secType};
        if ((ref($item) eq 'HASH') && defined($item->{ciphers})) {
          foreach (@{$item->{ciphers}}) {
            if (defined($_->{strength}) && defined($_->{name})) {
              $cipher{$secType}{$_->{strength}} .= "$_->{name} ";
              $info{WeakCipherSuite} |= ($_->{strength} eq 'weak');
            }
          }
          $secType =~ s/\.//g;
          $info{$secType} = 1;
        }
      }
    }        
  }
  $info{Selfsigned} |= (defined($info{SubjectCN}) && defined($info{IssuerCN}) && ($info{SubjectCN} eq $info{IssuerCN}));
  $self->{Info}->{Script} = \%info if (%info);
}
  

sub outputInfo() {
  my $self = shift;
  
  my @infoarr = ();
  # From File
  push (@infoarr, $self->{Info}->{File}->{Date});
  push (@infoarr, $self->{Info}->{File}->{Region});

  # From Host
  push (@infoarr, $self->{Info}->{Host}->{Host_IP});
  push (@infoarr, $self->{Info}->{Host}->{Hostname});

  # From Script
  if (defined($self->{Info}->{Script}->{HTML_Title})) {
    $self->{Info}->{Script}->{HTML_Title} =~ s/\r|\n|\;//g;
  }
  return 0 if (!$self->{Info}->{Script}->{KeyBits} || !$self->{Info}->{Script}->{CertKeyType});
  push (@infoarr, $self->{Info}->{Script}->{HTML_Title});
  push (@infoarr, $self->{Info}->{Script}->{SubjectCN});
  push (@infoarr, $self->{Info}->{Script}->{IssuerCN});
  push (@infoarr, $self->{Info}->{Script}->{Selfsigned});
  push (@infoarr, $self->{Info}->{Script}->{CertKeyType});
  push (@infoarr, $self->{Info}->{Script}->{KeyBits});
  push (@infoarr, $self->{Info}->{Script}->{CertSHA1});
  push (@infoarr, $self->{Info}->{Script}->{CertPEM});
  push (@infoarr, $self->{Info}->{Script}->{ValidFrom});
  push (@infoarr, $self->{Info}->{Script}->{ValidTo});
  push (@infoarr, $self->{Info}->{Script}->{WeakCipherSuite});
  push (@infoarr, $self->{Info}->{Script}->{SSLv1});
  push (@infoarr, $self->{Info}->{Script}->{SSLv2});
  push (@infoarr, $self->{Info}->{Script}->{SSLv3});
  push (@infoarr, $self->{Info}->{Script}->{TLSv10});
  push (@infoarr, $self->{Info}->{Script}->{TLSv11});
  push (@infoarr, $self->{Info}->{Script}->{TLSv12});
  push (@infoarr, $self->{Info}->{Script}->{CipherSet});

  @infoarr = map {defined($_) ? $_ : ''} @infoarr;

  # ggf. Ausgabedatei schreiben
  if ($self->{Ausgabedatei}) {
    my @infooutarr = ();
    # From File
    push (@infooutarr, $self->{Info}->{File}->{Date});
    push (@infooutarr, $self->{Info}->{File}->{Region});

    # From Host
    push (@infooutarr, $self->{Info}->{Host}->{Host_IP});
    push (@infooutarr, $self->{Info}->{Host}->{Hostname});

    # From Script
    push (@infooutarr, $self->{Info}->{Script}->{HTML_Title});
    push (@infooutarr, $self->{Info}->{Script}->{SubjectCN});
    push (@infooutarr, $self->{Info}->{Script}->{IssuerCN});
    push (@infooutarr, $self->{Info}->{Script}->{Selfsigned});
    push (@infooutarr, $self->{Info}->{Script}->{CertKeyType});
    push (@infooutarr, $self->{Info}->{Script}->{KeyBits});
    push (@infooutarr, $self->{Info}->{Script}->{CertSHA1});
    # push (@infooutarr, $self->{Info}->{Script}->{CertPEM});
    push (@infooutarr, $self->{Info}->{Script}->{ValidFrom});
    push (@infooutarr, $self->{Info}->{Script}->{ValidTo});
    push (@infooutarr, $self->{Info}->{Script}->{WeakCipherSuite});
    # push (@infooutarr, $self->{Info}->{Script}->{SSLv1});
    # push (@infooutarr, $self->{Info}->{Script}->{SSLv2});
    # push (@infooutarr, $self->{Info}->{Script}->{SSLv3});
    # push (@infooutarr, $self->{Info}->{Script}->{TLSv10});
    # push (@infooutarr, $self->{Info}->{Script}->{TLSv11});
    # push (@infooutarr, $self->{Info}->{Script}->{TLSv12});
    # push (@infooutarr, $self->{Info}->{Script}->{CipherSet});

    @infooutarr = map {defined($_) ? $_ : ''} @infooutarr;

    my $infostr = join('; ', @infooutarr);
    Trace->Log('Ausgabe', $infostr);
  }
  
  # ggf. DB-Eintrag schreiben
  if (Configuration->config('DB', 'RDBMS')) {
    DBAccess->execute(@infoarr) or Trace->Exit(0x101, 0, "Error: $DBI::errstr");
    DBAccess->autocommit();
    my $seq = DBAccess->getseq();
    # ggf. Cert schreiben
    if ($seq ne '-1' && $self->{Certdir}) {
      my $filename = File::Spec->catfile(File::Spec->canonpath($self->{Certdir}), sprintf('%010s', $seq) . '.pem');
      Utils::writeFile(SRCCONTENT => $self->{Info}->{Script}->{CertPEM}, 
                       DSTFILE    => $filename, 
                       FORCE      => 1);
    }
  }
}

1;
