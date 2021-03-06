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
  if (Configuration->config('IO', 'Statistiskdatei')) {
    my $tmp = File::Spec->canonpath(Utils::extendString(Configuration->config('IO', 'Statistiskdatei')));
    if (Utils::mk_dir($tmp)) {
      Trace->Exit(0x104, 0, dirname($tmp), $@);
    }
    $self->{Statistiskdatei} = $tmp;
  }
  if (Configuration->config('IO', 'Certverzeichnis')) {
    my $tmp  = File::Spec->canonpath(Utils::extendString(Configuration->config('IO', 'Certverzeichnis') . "/dummy"));
     if (Utils::mk_dir($tmp)) {
      Trace->Exit(0x105, 0, dirname(File::Spec->canonpath(Utils::extendString(Configuration->config('IO', 'Certverzeichnis')))), $@);
    }
    $self->{Certdir}      = File::Spec->canonpath(Utils::extendString(Configuration->config('IO', 'Certverzeichnis')));
  }

  # DB-Zugriff
  if (Configuration->config('DB', 'RDBMS')) {
    # Anlegen des Cursors (0) zum Speichern der neuen Wert in die DB
    my $stmt = 'INSERT INTO ' . Configuration->config('DB', 'DB') . ' (Date, Region, Host_IP, Hostname, Port, HTML_Title, SubjectCN, IssuerCN, Selfsigned, CertKeyType, KeyBits, CertSHA1, CertPEM, ValidFrom, ValidTo, WeakCipherSuite, SSLv1, SSLv2, SSLv3, TLSv10, TLSv11, TLSv12, CipherSet) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)';
    # @@@ my $stmt = 'INSERT INTO ' . Configuration->config('DB', 'DB') . ' (Date, Region, Host_IP, Hostname, HTML_Title, SubjectCN, IssuerCN, Selfsigned, CertKeyType, KeyBits, CertSHA1, CertPEM, ValidFrom, ValidTo, WeakCipherSuite, SSLv1, SSLv2, SSLv3, TLSv10, TLSv11, TLSv12, CipherSet) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)';
    DBAccess->prepare($stmt, 0) or Trace->Exit(0x100, 0, "Error: $DBI::errstr");
    
    # Anlegen des Cursors (1) zum Ermitteln der Anreicherungswerte
    # KOMMENTAR ENTFERNEN UND AENDERN
    $stmt = 'SELECT Value1, Value2, Value3 FROM ' . Configuration->config('DB', 'ENRICHMENTDB') . ' WHERE SVal1 = ? AND SVal2 = ?';
#    DBAccess->prepare($stmt, 1) or Trace->Exit(0x100, 0, "Error: $DBI::errstr");

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
    Trace->Trc('S', 1, 0x00002, "$routine $@ $! $?");
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
  # 
  # Proc 1
  #
  my $self = shift;
  
  my $merker          = $self->{subroutine};
  $self->{subroutine} = (caller(0))[3];
  Trace->Trc('S', 3, 0x00001, $self->{subroutine}, CmdLine->argument(0));
  
  my $eingabe           = File::Spec->canonpath(Utils::extendString(Configuration->config('IO', 'Eingabeverzeichnis')));
  Trace->Trc('I', 2, 0x02100, $eingabe);
  $self->{fileList}     = Utils::fetchFileList($eingabe);
  Trace->Trc('I', 2, 0x02101, join('|', $self->{fileList}));

  Trace->Trc('S', 3, 0x00002, $self->{subroutine});
  $self->{subroutine} = $merker;

  return 1;
}


sub nextFile {
  # 
  # Proc 2
  #
  my $self = shift;
  my @args = @_;
  
  my $merker          = $self->{subroutine};
  $self->{subroutine} = (caller(0))[3];
  Trace->Trc('S', 3, 0x00001, $self->{subroutine}, CmdLine->argument(0));
  
  my $rc = shift(@{$self->{fileList}});
  Trace->Trc('I', 2, 0x02200, $rc);
  
  Trace->Trc('S', 3, 0x00002, $self->{subroutine});
  $self->{subroutine} = $merker;

  return $rc;
}


sub getInfo() {
  # 
  # Proc 3
  #
  my $self   = shift;
  my $type   = shift;
  my $object = shift;
  
  my $merker          = $self->{subroutine};
  $self->{subroutine} = (caller(0))[3];
  Trace->Trc('S', 3, 0x00001, $self->{subroutine}, CmdLine->argument(0));

  Trace->Trc('I', 2, 0x02300, $type);
  undef($self->{Info}->{$type});
  my %args = Configuration->config('NMAP');
  foreach (keys %args) {
    if ($_ =~ m/^${type}\s+([^\s]+)$/) {
      $self->{Info}->{$type}->{$args{$_}} = join(' ', $object->$1) if $args{$_};
      Trace->Trc('I', 2, 0x02301, $type, $args{$_}, $_, $self->{Info}->{$type}->{$args{$_}});
    }
  }
  
  Trace->Trc('S', 3, 0x00002, $self->{subroutine});
  $self->{subroutine} = $merker;

  return 0;;
}
  

sub analyseThis () {
  # 
  # Proc 4
  #
  my $self    = shift;
  my $service = shift;
  
  my $merker          = $self->{subroutine};
  $self->{subroutine} = (caller(0))[3];
  Trace->Trc('S', 3, 0x00001, $self->{subroutine}, CmdLine->argument(0));

  my %info;
  foreach ('Selfsigned', 'WeakCipherSuite', 'SSLv1', 'SSLv2', 'SSLv3', 'TLSv10', 'TLSv11', 'TLSv12') {$info{$_} = 0}
  foreach my $script (keys(%{$service->{script}})) {
    Trace->Trc('I', 2, 0x02400, $script);
    my $content = $service->scripts($script)->{contents};
    my $output  = $service->scripts($script)->{output};
    
    if ($script eq "html-title-db") {
      $info{HTML_Title} = $output;
    } elsif ($script eq "my-ssl-cert") {
      foreach (keys(%$content)) {
        Trace->Trc('I', 2, 0x02401, $_, $script);
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
        Trace->Trc('I', 2, 0x02401, $secType, $script);
        my $item = $content->{$secType};
        if ((ref($item) eq 'HASH') && defined($item->{ciphers})) {
          foreach (@{$item->{ciphers}}) {
            if (defined($_->{strength}) && defined($_->{name})) {
              Trace->Trc('I', 2, 0x02402, $_->{name}, $secType, $script);
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

  Trace->Trc('S', 3, 0x00002, $self->{subroutine});
  $self->{subroutine} = $merker;

  return 1;
}
  

sub outputInfo() {
  # 
  # Proc 4
  #
  my $self = shift;
  
  my $merker          = $self->{subroutine};
  $self->{subroutine} = (caller(0))[3];
  Trace->Trc('S', 1, 0x00001, $self->{subroutine}, CmdLine->argument(0));
  
  # Replace CR, LR and Semicolon if present in HTML_Title
  if (defined($self->{Info}->{Script}->{HTML_Title})) {
    $self->{Info}->{Script}->{HTML_Title} =~ s/\r|\n|\;//g;
  }
  
  my @infoarr = ();

  # ggf. Ausgabedatei schreiben
  if ($self->{Ausgabedatei}) {
    @infoarr = ();
    # From File
    push (@infoarr, $self->{Info}->{File}->{Date});
    push (@infoarr, $self->{Info}->{File}->{Region});

    # From Host
    push (@infoarr, $self->{Info}->{Host}->{Host_IP});
    push (@infoarr, $self->{Info}->{Host}->{Hostname});

    # From Service
    push (@infoarr, $self->{Info}->{Service}->{Port});

    # From Script
    foreach ('HTML_Title', 'SubjectCN', 'IssuerCN', 'Selfsigned', 'CertKeyType', 'KeyBits', 'CertSHA1', 
             'ValidFrom', 'ValidTo', 'WeakCipherSuite', 'SSLv1', 'SSLv2', 'SSLv3', 'TLSv10', 'TLSv11', 
             'TLSv12') {
      push (@infoarr, $self->{Info}->{Script}->{$_});
    }

    @infoarr = map {defined($_) ? $_ : ''} @infoarr;

    my $infostr = join('; ', @infoarr);
    Trace->Log('Ausgabe', $infostr);
    Trace->Trc('I', 2, 0x02500, $self->{Ausgabedatei}, $infostr);
  }

  @infoarr = ();
  # From File
  push (@infoarr, $self->{Info}->{File}->{Date});
  push (@infoarr, $self->{Info}->{File}->{Region});

  # From Host
  push (@infoarr, $self->{Info}->{Host}->{Host_IP});
  push (@infoarr, $self->{Info}->{Host}->{Hostname});

  # From Service
  push (@infoarr, $self->{Info}->{Service}->{Port});

  # From Script
  foreach ('HTML_Title', 'SubjectCN', 'IssuerCN', 'Selfsigned', 'CertKeyType', 'KeyBits', 'CertSHA1', 
           'CertPEM', 'ValidFrom', 'ValidTo', 'WeakCipherSuite', 'SSLv1', 'SSLv2', 'SSLv3', 'TLSv10', 
           'TLSv11', 'TLSv12', 'CipherSet') {
    push (@infoarr, $self->{Info}->{Script}->{$_})
  }

  @infoarr = map {defined($_) ? $_ : ''} @infoarr;

  
  if (Configuration->config('DB', 'RDBMS')) {
    # Anreichern der Datenbank mit Werten aus einer anderen Datenbank
    # Beispiel SELECT-Statement: SELECT (Value1, Value2, Value3 FROM ' . Configuration->config('DB', 'ENRICHMENTDB') . ' WHERE SVal1 = ? AND SVal2 = ?';
    # KOMMENTAR ENTFERNEN UND AENDERN
 #   DBAccess->setidx(1);
 #   Trace->Trc('D', 2, 0x02501, $self->{Info}->{Script}->{SubjectCN}, $self->{Info}->{Script}->{ValidFrom}, $self->{Info}->{Script}->{ValidTo});
 #   DBAccess->execute($self->{Info}->{Script}->{SubjectCN}, $self->{Info}->{Script}->{ValidFrom}, $self->{Info}->{Script}->{ValidTo}) or Trace->Exit(0x101, 0, "Error: $DBI::errstr");
 #   if (my $ref = Utils::hmap(sub {defined($_) ? $_ : ''}, DBAccess->fetchrow_hashref())) {
 #     Trace->Trc('D', 2, 0x02502, $$ref{VALUE1}, $$ref{VALUE2}, $$ref{VALUE3});
 #     push (@infoarr, $$ref{VALUE1});
 #     push (@infoarr, $$ref{VALUE2});
 #     push (@infoarr, $$ref{VALUE3});
 #   }

    # ggf. DB-Eintrag schreiben
    DBAccess->setidx(0);
    my $infostr = join('; ', @infoarr);
    Trace->Trc('D', 2, 0x02503, $infostr);

    DBAccess->execute(@infoarr) or Trace->Exit(0x101, 0, "Error: $DBI::errstr");
    DBAccess->autocommit();
    my $seq = DBAccess->getseq();
    # ggf. Cert schreiben
    if ($seq ne '-1' && $self->{Certdir}) {
      my $filename = File::Spec->catfile(File::Spec->canonpath($self->{Certdir}), sprintf('%010s', $seq) . '.pem');
      Trace->Trc('I', 2, 0x02504, $filename);
      Utils::writeFile(SRCCONTENT => $self->{Info}->{Script}->{CertPEM}, 
                       DSTFILE    => $filename, 
                       FORCE      => 1);
    }
  }

  Trace->Trc('S', 1, 0x00002, $self->{subroutine});
  $self->{subroutine} = $merker;

  return 1;
}

1;
