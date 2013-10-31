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
  
  if (defined($pversion)) {
    $pversion =~ m/^([^\s]*)\sR([0-9]*)$/;
    my ($pVer, $pRel) = ($1, $2);
    $VERSION = $oRel > $pRel ? "$pVer R$oRel" : "$pVer R$pRel";
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
  
  Trace->Trc('S', 1, 0x00001, Configuration->prg, $VERSION . " (" . $$ . ")" . " Test: " . Trace->test . " Parameter: " . CmdLine->new()->{ArgStrRAW});
  
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
  
  # Test der benoetigten INI-Variablen
  # DB-Zugriff
  #$self->Exit(1, 0, 0x08002, 'DB', 'DB')                if (!defined($self->config('DB', 'DB')));

  # Ergebnisausgabe und Sicherung
  #$self->Exit(1, 0, 0x08002, 'Ausgabe', 'Out')             if (!defined($self->config('Ausgabe', 'Out')));

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
  $self->{Ausgabedatei} = File::Spec->canonpath(Utils::extendString(Configuration->config('IO', 'Ausgabedatei')));
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
  my %args = Configuration->config('NMAP ' . $type);
  foreach (keys %args) {
    $self->{Info}->{$type}->{$args{$_}} = join(' ', $object->$_) if $args{$_};
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
        if (($_ eq 'validity') && defined($item->{notBefore}))  {$info{ValidFrom}   = $item->{notBefore}}
        if (($_ eq 'validity') && defined($item->{notAfter}))   {$info{ValidTo}     = $item->{notAfter}}
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
  
  my $infostr;
  # From File
  $infostr .= "$self->{Info}->{File}->{Date}; ";
  $infostr .= "$self->{Info}->{File}->{Region}; ";

  # From Host
  $infostr .= "$self->{Info}->{Host}->{Host_IP}; ";
  $infostr .= "$self->{Info}->{Host}->{Hostname}; ";
   
  # From OS
  
  # From Service
  
  # From Script
  $infostr .= "$self->{Info}->{Script}->{HTML_Title}; ";
  $infostr .= "$self->{Info}->{Script}->{SubjectCN}; ";
  $infostr .= "$self->{Info}->{Script}->{IssuerCN}; ";
  $infostr .= "$self->{Info}->{Script}->{Selfsigned}; ";
  $infostr .= "$self->{Info}->{Script}->{CertKeyType}; ";
  $infostr .= "$self->{Info}->{Script}->{KeyBits}; ";
  $infostr .= "$self->{Info}->{Script}->{CertSHA1}; ";
  $infostr .= "$self->{Info}->{Script}->{CertPEM}; ";
  $infostr .= "$self->{Info}->{Script}->{ValidFrom}; ";
  $infostr .= "$self->{Info}->{Script}->{ValidTo}; ";
  $infostr .= "$self->{Info}->{Script}->{WeakCipherSuite}; ";
  $infostr .= "$self->{Info}->{Script}->{SSLv1}; ";
  $infostr .= "$self->{Info}->{Script}->{SSLv2}; ";
  $infostr .= "$self->{Info}->{Script}->{SSLv3}; ";
  $infostr .= "$self->{Info}->{Script}->{TLSv10}; ";
  $infostr .= "$self->{Info}->{Script}->{TLSv11}; ";
  $infostr .= "$self->{Info}->{Script}->{TLSv12}; ";
  $infostr .= "$self->{Info}->{Script}->{CipherSet}";
  
  if (defined($self->{Ausgabedatei}) && open(my $outfile, ">>", $self->{Ausgabedatei})) {
    print $outfile "$infostr\n";
    close $outfile;
  }
}

1;
