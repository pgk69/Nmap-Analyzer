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
  #$self->Exit(1, 0, 0x08002, 'DB', 'MC_DB')                if (!defined($self->config('DB', 'MC_DB')));
  #$self->Exit(1, 0, 0x08002, 'DB', 'FID_DB')               if (!defined($self->config('DB', 'FID_DB')));

  # Ergebnisausgabe und Sicherung
  #$self->Exit(1, 0, 0x08002, 'Ausgabe', 'Log')             if (!defined($self->config('Ausgabe', 'Log')));
  #$self->Exit(1, 0, 0x08002, 'Ausgabe', 'Err')             if (!defined($self->config('Ausgabe', 'Err')));
  #$self->Exit(1, 0, 0x08002, 'Ausgabe', 'Out')             if (!defined($self->config('Ausgabe', 'Out')));
  #$self->Exit(1, 0, 0x08002, 'Ausgabe', 'SICHERUNG')       if (!defined($self->config('Ausgabe', 'SICHERUNG')));

  if (Configuration->config('Prg', 'LockFile')) {
    $self->{LockFile} = Utils::extendString(Configuration->config('Prg', 'LockFile'), "BIN|$Bin|SCRIPT|" . uc($Script));
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
  my @args = @_;
  
  my $eingabe = Configuration->config('Eingabe', 'Eingabeverzeichnis');
  $self->{fileList} = Utils::fetchFileList($eingabe);
}


sub nextFile {
  my $self = shift;
  my @args = @_;
  
  my $rc = shift(@{$self->{fileList}});
  
  return $rc;
}


sub getInfo() {
  my $self   = shift;
  my $target = shift;
  my $object = shift;
  my @args   = @_;
  
  foreach (@args) {
    $target->{$_} = join(' ', $object->$_);
  }
  
  return 0;;
}
  

sub getCipher () {
  my $self    = shift;
  my $service = shift;

  my @scriptList = $service->scripts;
  
  foreach my $scriptName (@scriptList) {
    my @scriptContent = $service->scripts($scriptName); 
    print Dumper($scriptName, @scriptContent); 
    my $breackpoint;
    
    # html-title-db
    if      ($scriptName eq "html-title-db") {

    } elsif ($scriptName eq "my-ssl-cert") {

    } elsif ($scriptName eq "my-ssl-enum-ciphers") {

    } elsif ($scriptName eq "") {

    } elsif ($scriptName eq "") {

    } elsif ($scriptName eq "") {

    }        
  }
  
  # CERTIFICATE DETAILS
#  foreach my $scr (@scriptList) {
#    if ($scr eq "html-title-db") { 
#      $html_title = [string]$scr.output
#      $html_title = $html_title.Replace( "`n", "").Replace("`r", "").Replace(",", "")
#    } elseif ($scr.id -eq "my-ssl-cert") { 
#      foreach ($t in $scr.table) {
#        if ($t.key -eq "subject") {
#          foreach ($e in $t.elem) {
#            if ($e.key -eq "commonName") { 
#              $subject_common_name = $e.InnerXML
#            }
#          }
#        } elseif ($t.key -eq "issuer") {
#          foreach ($e in $t.elem) {
#            if ($e.key -eq "commonName") { 
#              $issuer_common_name = $e.InnerXML
#            }
#          }
#        } elseif ($t.key -eq "pubkey") {
#          foreach ($e in $t.elem) {
#            if ($e.key -eq "type") { 
#              $cert_key_type = $e.InnerXML
#            }
#            if ($e.key -eq "bits") { 
#              $cert_key_bits = $e.InnerXML
#            }
#          }
#        } elseif ($t.key -eq "validity") {
#          foreach ($e in $t.elem) {
#            if ($e.key -eq "notBefore") { 
#              $cert_not_before = [string]$e.InnerXML
#              $cert_not_before = $cert_not_before.Substring(0,10)
#            }
#            if ($e.key -eq "notAfter") { 
#              $cert_not_after = [string]$e.InnerXML
#              $cert_not_after = $cert_not_after.Substring(0,10)
#            }
#          }          
#        } else {
#          # ERROR HANDLING !!!!
#        }
#      }
#         
#      $cert_filename = Write-Certificate($scr)
#      # FIXME INVOKE OPENSSL CERTIFICATE ANALYSIS HERE
#    } elseif ($scr.id -eq "my-ssl-enum-ciphers" )
#    # SCAN FOR WEAK SSL CIPHERS
#      {
#         foreach( $tv in $scr.table )
#         {
#                  $SSLTLS_version = $tv.key
#          $SSLTLS_supported["$SSLTLS_version"] = "true"
#          
#          # FIXME USE GT IT SECURITY APPROVED CIPHERSUITES
#          foreach( $t in $tv.table )
#          {
#                 if( $t.key -eq "ciphers" )
#             {
#                        foreach( $t2 in $t.table )
#                        {
#            
#                 $isweak = ""
#               $csuite = ""
#                           foreach( $e in $t2.elem )
#               {           
#                  if( $e.key -eq "strength" )
#                  {
#                     $isweak = $e.InnerXML
#                  }
#                  elseif( $e.key -eq "name")
#                  {
#                     $csuite = $e.InnerXML
#                  }
#               }                
#               
#                           if( $isweak -eq "weak" )
#                           {
#                  $cipher_suite_bad["$SSLTLS_version"] += "$csuite" + " "
#               }
#               else
#               {
#                  $cipher_suite_good["$SSLTLS_version"] += "$csuite" + " "
#               }
#                        }          
#             }
#                  }
#         }
#               $cipher_suite_weak = $scr.elem.InnerXML         
#      }
#     }
#     
#     if ( $subject_common_name -eq $issuer_common_name )
#     {
#        $self_signed = "true"
#     }   
#    }
}

1;
