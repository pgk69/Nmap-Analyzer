eval 'exec perl -wS $0 ${1+"$@"}'
  if 0;

#-------------------------------------------------------------------------------------------------
# Letzte Aenderung:     $Date:  $
#                       $Revision:  $
#                       $Author:  $
#
# Aufgabe:        - Ausfuehrbarer Code von nmapanalyze.pl
#
# $Id:  $
# $URL:  $
#-------------------------------------------------------------------------------------------------

# Letzte Aenderung: 

use 5.010;
use strict;
use vars qw($VERSION $SVN);

use constant SVN_ID => '($Id:  $)

$Author:  $ 

$Revision:  $ 
$Date:  $ 

$URL:  $

';

# Extraktion der Versionsinfo aus der SVN Revision
($VERSION = SVN_ID) =~ s/^(.*\$Revision: )([0-9]*)(.*)$/1.0 R$2/ms;
$SVN = $VERSION . ' ' . SVN_ID;

$| = 1;

# use lib $Bin . "/lib";       # fuer Aufruf mit voll qualifiziertem Pfad noetig
use lib "./lib";    # fuer perl2exe noetig

#use lib $Bin . "/lib/SPLIT"; # fuer Aufruf mit voll qualifiziertem Pfad noetig
#use lib "./lib/SPLIT";       # fuer perl2exe noetig

#
# Module
#
use CmdLine;
use Trace;
use Configuration;
use DBAccess;

use PROGRAMM;
use PROGRAMM::Modul1;
use PROGRAMM::Modul2;

use Fcntl;
use FindBin qw($Bin $Script $RealBin $RealScript);

#
# Variablendefinition
#

#
# Objektdefinition
#

# Option-Objekt: Liest und speichert die Kommandozeilenparameter
my $cmdLine = CmdLine->new('Client'  => 'client:s',
                           'Region'  => 'region:s',
                           'Partner' => 'partner:s');
$VERSION = $cmdLine->version($VERSION);

# Trace-Objekt: Liest und speichert die Meldungstexte; gibt Tracemeldungen aus
my $trace = Trace->new();
$VERSION = $trace->version($VERSION);

# Config-Objekt: Liest und speichert die Initialisierungsdatei
my $config = Configuration->new();
$VERSION = $config->version($VERSION);

# Datenbank-Objekt: Regelt dei Datenbankzugriffe
my $dbaccess = DBAccess->new();
$VERSION = $dbaccess->version($VERSION);

# Kopie des Fehlerkanals erstellen zur gelegentlichen Abschaltung
no warnings;
sysopen(MYERR, "&STDERR", O_WRONLY);
use warnings;

#
#################################################################
## main
##################################################################
#
$trace->Trc('S', 1, 0x00001, $config->prg, 
                             $VERSION .
                             " (" . $$ . ") " . 
                             "Test: " . $trace->test .
                             "  Parameter: " . $cmdLine->{ArgStrg});

# Test der Komandozeilenparameter
if (!$cmdLine->argument(0) || !$cmdLine->argument(1) ||
     $cmdLine->option('Help')|| $cmdLine->option('Version')) {
  $cmdLine->usage;
  if ($cmdLine->option('Help') || $cmdLine->option('Version')) {
    $trace->Exit(0, 1, 0x00002, $config->prg, $VERSION);
  }
  $trace->Exit(1, 0, 0x08003, $cmdLine->{ArgStrg});
}

my $prg;
eval {$prg = PROGRAMM->new()};
if ($@) {
  $prg->Exit(0, 1, 0x0ffff, $prg->prg, $VERSION);
}
$VERSION = $prg->version($VERSION);
$prg->set_pers_Var($prg->config('DB', 'FID_DB').'.fid_config', 'Start');

my $a;
my %b;

$a = $prg->config('Ausgabe', 'Log');
$a = $prg->config('Ausgabe');
$a = $prg->config();
$a = $prg->config('Ausgabe', 'Frog');
$a = $prg->config('Rausgabe', 'Frog');
$a = $prg->config('Rausgabe');

%b = $prg->config('Ausgabe', 'Log');
%b = $prg->config('Ausgabe');
%b = $prg->config();
%b = $prg->config('Ausgabe', 'Frog');
%b = $prg->config('Rausgabe', 'Frog');
%b = $prg->config('Rausgabe');

  

# Test der benoetigten Kommandline-Variablen
if ($prg->argument(0)) {
  $prg->{Eingabemaske} = $prg->argument(0)
} else {
  $prg->{Eingabemaske} = $prg->config('Eingabe', 'Fusionsliste')
}

# Anlegen der Dateien zum Log, Error-Log und Ausgabeliste sowie FMC  
$prg->Log('Log', $prg->config('Ausgabe', 'Log')) or $prg->Exit(1, 0, 0x00010, Utils::extendString($prg->config('Ausgabe', 'Log')));
if (my $logrc = $prg->Log('FMC', $prg->config('Ausgabe', 'FMC'), '0111')) {
  if ($logrc eq 'N') {
    $prg->Log('FMC', "ERSTEINTRAG") or $prg->Exit(1, 0, 0x00010, Utils::extendString($prg->config('Ausgabe', 'FMC')));
  }
} else {
  $prg->Exit(1, 0, 0x00010, $prg->config('Ausgabe', 'FMC'))
}

#--------------------------------------------------------------
# PRGRAMM-Start
#--------------------------------------------------------------
$prg->Log('Log', 0x10000, $prg->version());
$prg->Log('Log', 0x10001, $prg->prg, '', $cmdLine->{ArgStrg});



$prg->set_pers_Var($prg->config('DB', 'FID_DB').'.fid_config', 'Ende '.$cmdLine->{ArgStrg});
$prg->Exit(0, 1, 0x00002, $prg->prg, $VERSION);

exit 1;
