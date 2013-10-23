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
# use lib "./lib";    # fuer perl2exe noetig

#use lib $Bin . "/lib/NMAPANALYZE"; # fuer Aufruf mit voll qualifiziertem Pfad noetig
#use lib "./lib/NMAPANALYZE";       # fuer perl2exe noetig

#
# Module
#
use CmdLine;
use Trace;
use Configuration;
#use DBAccess;

use NMAPANALYZE;
# use NMAPANALYZE::Modul1;
# use NMAPANALYZE::Modul2;

use Fcntl;
use FindBin qw($Bin $Script $RealBin $RealScript);
use Data::Dumper;
use Nmap::Parser;

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
#$VERSION = DBAccess->new()->version($VERSION);

# Kopie des Fehlerkanals erstellen zur gelegentlichen Abschaltung
no warnings;
sysopen(MYERR, "&STDERR", O_WRONLY);
use warnings;

#
#################################################################
## main
##################################################################
#

# Test der Komandozeilenparameter
#if (!CmdLine->argument(0) || !CmdLine->argument(1) ||
#     CmdLine->option('Help')|| CmdLine->option('Version')) {
#  CmdLine->usage;
#  if (CmdLine->option('Help') || CmdLine->option('Version')) {
#    Trace->Exit(0, 1, 0x00002, Configuration->prg, $VERSION);
#  }
#  Trace->Exit(1, 0, 0x08003, join(' ', CmdLine->argument()));
#}

my $scan;
eval {$scan = NMAPANALYZE->new()};
if ($@) {
  Trace->Exit(1, 1, 0x0ffff, Configuration->prg, $VERSION);
}

#--------------------------------------------------------------
# PRGRAMM-Start
#--------------------------------------------------------------
$scan->lese_Fileliste();

my $str_headline = "Date,Region,Host_IP,Hostname,SSLTLS-hit,HTML_Title,SubjectCN,IssuerCN,Selfsigned,CertKeyType,KeyBits,ValidFrom,ValidTo,WeakCipherSuite";

# SSL Protocols
my @SSLTLSVer = ("SSLv1", "SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2");

# GT IT SECURITY APPROVED CIPHER SUITES, See dbPolicyportal "SSL/TLS Standard"
my @strong_ciphers = ("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_256_GCM_SHA384", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA", "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_RSA_WITH_RC4_128_SHA" );

while (my $file_xml = $scan->nextFile()) {
  if ($file_xml =~ m/scanresult\-(20[0-9]{2}[0-1][0-9][0-3][0-9])_[0-2][0-9][0-5][0-9][0-5][0-9]_(Europe|Asia|UK|US).*$/) {
    my ($date, $region) = ($1, $2);

    my $np = new Nmap::Parser->parsefile($file_xml);
    my @host_list = $np->all_hosts();

    my (%hostinfo, %serviceinfo,%osinfo);
    my $infostr;
    foreach my $host (@host_list) {
      my @ports = $host->tcp_open_ports();
      if (@ports) {
        # Hostinfos
        undef(%hostinfo);
        $hostinfo{status}            = $host->status() || '';
        $hostinfo{addr}              = $host->addr() || '';
        $hostinfo{addrtype}          = $host->addrtype() || '';
        $hostinfo{all_hostnames_str} = join(' ', $host->all_hostnames() || '');
        $hostinfo{all_hostnames}     = $host->all_hostnames() || '';
        # $hostinfo{extraports_count} = $host->extraports_count() || '';
        # $hostinfo{extraports_state} = $host->extraports_state() || ''; 
        $hostinfo{hostname}         = $host->hostname() || '';
        # $hostinfo{ipv4_addr}        = $host->ipv4_addr() || '';
        # $hostinfo{ipv6_addr}        = $host->ipv6_addr() || '';
        # $hostinfo{mac_addr}         = $host->mac_addr() || '';
        # $hostinfo{mac_vendor}       = $host->mac_vendor() || '';
        # $hostinfo{distance}         = $host->distance() || '';
        # $hostinfo{trace_error}      = $host->trace_error() || '';

        # OS Infos     
        my $os = $host->os_sig();   
        undef(%osinfo);
        $osinfo{all_names}       = join(' ', $os->all_names() || '');
        $osinfo{class_accuracy}  = join(' ', $os->class_accuracy() || '');
        $osinfo{class_count}     = $os->class_count() || '';
        $osinfo{names}           = join(' ', $os->names() || '');
        $osinfo{name_accuracy}   = join(' ', $os->name_accuracy() || '');
        $osinfo{name_count}      = $os->name_count() || '';
        $osinfo{osfamily}        = join(' ', $os->osfamily() || '');
        $osinfo{osgen}           = join(' ', $os->osgen() || '');
        $osinfo{portused_closed} = $os->portused_closed() || '';
        $osinfo{portused_open}   = $os->portused_open() || '';
        $osinfo{os_fingerprint}  = $os->os_fingerprint() || '';
        $osinfo{type}            = join(' ', $os->type() || '');
        $osinfo{vendor}          = join(' ', $os->vendor() || '');

        foreach my $portid (@ports) {
          # Port Infos        
          my $service          = $host->tcp_service($portid);
          undef(%serviceinfo);
          $serviceinfo{tcp_open_port} = $portid;
          $serviceinfo{name}        = $service->name() || '';
          $serviceinfo{proto}       = $service->proto() || '';
          $serviceinfo{confidence}  = $service->confidence() || '';
          $serviceinfo{extrainfo}   = $service->extrainfo() || '';
          $serviceinfo{method}      = $service->method() || '';
          $serviceinfo{owner}       = $service->owner() || '';
          $serviceinfo{product}     = $service->product() || '';
          $serviceinfo{port}        = $service->port() || '';
          $serviceinfo{rpcnum}      = $service->rpcnum() || '';
          $serviceinfo{tunnel}      = $service->tunnel() || '';
          $serviceinfo{fingerprint} = $service->fingerprint() || '';
          $serviceinfo{scripts}     = join(' ', $service->scripts() || '');

          $infostr                  = "$date;$region;";
          foreach (keys(%hostinfo))    {$infostr .= "$_; $hostinfo{$_};"   }
          foreach (keys(%osinfo))      {$infostr .= "$_; $osinfo{$_};"     }
          foreach (keys(%serviceinfo)) {$infostr .= "$_; $serviceinfo{$_};"}
          print "$infostr\n";
        }
      }
    }
  } 
}


Trace->Exit(0, 1, 0x00002, Configuration->prg, $VERSION);

exit 1;
