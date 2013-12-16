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

#
# Module
#
use Fcntl;
use FindBin qw($Bin $Script $RealBin $RealScript);
use Data::Dumper;
use Nmap::Parser;

use lib $Bin . "/lib";
use lib $Bin . "/lib/NMAPANALYZE";
use lib $Bin . "/../Framework/lib";

use CmdLine;
use Trace;
use Configuration;
#use DBAccess;

use NMAPANALYZE;
# use NMAPANALYZE::Modul1;
# use NMAPANALYZE::Modul2;

#
# Variablendefinition
#

#
# Objektdefinition
#

# Option-Objekt: Liest und speichert die Kommandozeilenparameter
$VERSION = CmdLine->new()->version($VERSION);

# Trace-Objekt: Liest und speichert die Meldungstexte; gibt Tracemeldungen aus
$VERSION = Trace->new()->version($VERSION);

# Config-Objekt: Liest und speichert die Initialisierungsdatei
$VERSION = Configuration->new()->version($VERSION);

# Datenbank-Objekt: Regelt dei Datenbankzugriffe
$VERSION = DBAccess->new()->version($VERSION);

# Kopie des Fehlerkanals erstellen zur gelegentlichen Abschaltung
no warnings;
sysopen(MYERR, "&STDERR", O_WRONLY);
use warnings;

#
#################################################################
## main
##################################################################
#

my $scan;
eval {$scan = NMAPANALYZE->new()};
if ($@) {
  Trace->Exit(1, 1, 0x0ffff, Configuration->prg, $VERSION);
}

#--------------------------------------------------------------
# PRGRAMM-Start
#--------------------------------------------------------------
$scan->lese_Fileliste();

my @infoHeadline = ('Date' ,'Region',
                    'Host_IP', 'Hostname',
                    'HTML_Title', 
                    'SubjectCN', 'IssuerCN', 'Selfsigned', 'CertKeyType', 'KeyBits', 
                    'CertSHA1', 'CertPEM',                   
                    'ValidFrom', 'ValidTo',
                    'WeakCipherSuite', 'SSLv1', 'SSLv2', 'SSLv3', 'TLSv10', 'TLSv11', 'TLSv12',
                    'CipherSet');
                    
if ($scan->{Ausgabedatei}) {
  if (!Trace->Log('Ausgabe', $scan->{Ausgabedatei}, '0111')) {
    Trace->Exit(0x105, 0, $scan->{Ausgabedatei}, $@);
  }
}

while (my $file_xml = $scan->nextFile()) {
  if ($file_xml =~ m/scanresult\-(20[0-9]{2}[0-1][0-9][0-3][0-9])_[0-2][0-9][0-5][0-9][0-5][0-9]_(Europe|Asia|UK|US).*$/) {
    ($scan->{Info}{File}{Date}, $scan->{Info}{File}{Region}) = ($1, $2);

    my $np = new Nmap::Parser->parsefile($file_xml);
    my @host_list = $np->all_hosts();

    my $infostr;
    foreach my $host (@host_list) {
      my @ports = $host->tcp_open_ports();
      if (@ports) {
        # Hostinfos
        $scan->getInfo('Host', $host);

        # OS Infos     
        # $scan->getInfo('OS', $host->os_sig());

        foreach my $portid (@ports) {
          # Port Infos        
          $scan->getInfo('Service', $host->tcp_service($portid));
          $scan->{Info}{Service}{_tcp_open_port} = $portid;

          if ($scan->{Info}{Service}{_scripts}) {
            $scan->analyseThis($host->tcp_service($portid));
            $scan->outputInfo();
          }
 
#          $scan->outputInfo();
        }
      }
    }
  } 
  undef($scan->{Info});
}

if (Configuration->config('DB', 'RDBMS')) {
  DBAccess->setidx(0);
  DBAccess->commit();
  DBAccess->finish();
  DBAccess->setidx(1);
  DBAccess->commit();
  DBAccess->finish();
}


Trace->Exit(0, 1, 0x00002, Configuration->prg, $VERSION);

exit 1;
