# Get all XML-Scan files
# PROTOTYPE: Henrik Koy 2013-10-06
# POWERSHELL 2.0

### GLOBALS ###

# SSL Protocols
$SSLTLSVer = @("SSLv1", "SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2")

# GT IT SECURITY APPROVED CIPHER SUITES, See dbPolicyportal "SSL/TLS Standard"
$strong_ciphers = @("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_256_GCM_SHA384", "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA", "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "TLS_RSA_WITH_RC4_128_SHA" )

# REGIONS 
$regions = @("Europe", "Asia", "UK", "US")

# PATH ENVIRONMENTS
# FIXME

# OUTPUT FILE
$csv_filename = "scan.csv"

# FLAGS
$dump_certs = "false"


### HELPER ###

#####################################################
# CONVERTS UNIX TIME VALUE IN DATETIME OBJECT
function Convert-UnixTimeToDateTime([int]$UnixTime)
{
   (New-Object DateTime(1970, 1, 1, 0, 0, 0, 0, [DateTimeKind]::Utc)).AddSeconds($UnixTime)
}

#####################################################
# WRITES CERTIFICATE TO FILE (PEM FORMAT)
function Write-Certificate($t)
{
    [string]$pem_filename = "" 
	foreach( $e in $t.elem )
	{
		if( ($dump_certs -eq "true") -and ($e.key -eq "pem") )
		{ 
		    $pem_filename = ".\$host_name$host_ip.pem"
			$e.InnerXML >> $pem_filename
		}
	}
	
	return $pem_filname
}

### GLOBALS ###
$files = Get-ChildItem *.xml

#### Write-Host $str_headline
$str_headline = "Date,Region,Host_IP,Hostname,SSLTLS-hit,HTML_Title,SubjectCN,IssuerCN,Selfsigned,CertKeyType,KeyBits,ValidFrom,ValidTo,WeakCipherSuite"
foreach ( $item in $SSLTLSVer )
{
   $str_headline += "," + "$item"
}
$str_headline >> $csv_filename

# run through each scan
[int]$counter = 0
foreach( $file in $files ) 
{
   [xml]$xmlcontent=Get-Content $file

   $str_region = ""
   $scan_date = Convert-UnixTimeToDateTime( [int]$xmlcontent.nmaprun.start )
   $str_date = "{0:yyyy-MM-dd}" -f [datetime]$scan_date 

   $str_subnet = ""
   $str_time = "" 
	
   foreach( $x in $regions )
   {
      $s = [string]$file 
      if( $s.Contains( $x ) )
	  {
	     $str_region = $x
	  }
   }

   $counter++
   Write-Host $counter $file

   
   # run through each IP
   foreach( $hst in $xmlcontent.nmaprun.host )
   {
	  $host_ip = $hst.address.addr
	  $host_name = $hst.hostnames.hostname.name
	  $html_title = ""
	  $SSLTLS_hit = "false"
	  $subject_common_name = ""
	  $issuer_common_name = ""
	  $self_signed = "false"
	  $cert_key_type = ""
	  $cert_key_bits = ""
	  $cert_not_before = ""
	  $cert_not_after = ""
	 
	  $cipher_suite_good = @{}
	  $cipher_suite_bad  = @{}
	  $SSLTLS_supported  = @{}
	  foreach( $item in $SSLTLSVer )
	  {
		 $cipher_suite_good.Add( "$item", "" )
		 $cipher_suite_bad.Add( "$item", "" )
		 $SSLTLS_supported.Add( "$item", "false" )		   
	  }
	  $cipher_suite_weak = "false"

	  # SSL CONNECTION IS OPEN:
      if( $hst.ports.port.state.state -eq "open" )
	  {
		 $SSLTLS_hit = "true"
		 
		 # CERTIFICATE DETAILS
		 foreach( $scr in $hst.ports.port.script )
		 {
		    if( $scr.id -eq "html-title-db" )
			{ 
			   $html_title = [string]$scr.output
			   $html_title = $html_title.Replace( "`n", "").Replace("`r", "").Replace(",", "")
			}
		    elseif( $scr.id -eq "my-ssl-cert" )
			{ 
			   foreach( $t in $scr.table )
			   {
			      if( $t.key -eq "subject" )
				  {
				     foreach( $e in $t.elem )
			         {
			            if( $e.key -eq "commonName" )
				        { 
				           $subject_common_name = $e.InnerXML
				        }
			         }
				  }
				  elseif( $t.key -eq "issuer" )
				  {
				     foreach( $e in $t.elem )
			         {
			            if( $e.key -eq "commonName" )
				        { 
				           $issuer_common_name = $e.InnerXML
				        }
			         }
				  }
				  elseif( $t.key -eq "pubkey" )
				  {
				     foreach( $e in $t.elem )
			         {
			            if( $e.key -eq "type" )
				        { 
				           $cert_key_type = $e.InnerXML
				        }
			            if( $e.key -eq "bits" )
				        { 
				           $cert_key_bits = $e.InnerXML
				        }
			         }
			      }
				  elseif( $t.key -eq "validity" )
				  {
				     foreach( $e in $t.elem )
			         {
			            if( $e.key -eq "notBefore" )
				        { 
				           $cert_not_before = [string]$e.InnerXML
						   $cert_not_before = $cert_not_before.Substring(0,10)
				        }
			            if( $e.key -eq "notAfter" )
				        { 
				           $cert_not_after = [string]$e.InnerXML
						   $cert_not_after = $cert_not_after.Substring(0,10)
				        }
			         }				  
				  }
				  else
				  {
				     # ERROR HANDLING !!!!
				  }
			   }
			   
			   $cert_filename = Write-Certificate($scr)
			   # FIXME INVOKE OPENSSL CERTIFICATE ANALYSIS HERE
			}
			# SCAN FOR WEAK SSL CIPHERS
			elseif( $scr.id -eq "my-ssl-enum-ciphers" )
			{
			   foreach( $tv in $scr.table )
			   {
                  $SSLTLS_version = $tv.key
				  $SSLTLS_supported["$SSLTLS_version"] = "true"
				  
				  # FIXME USE GT IT SECURITY APPROVED CIPHERSUITES
				  foreach( $t in $tv.table )
				  {
  			         if( $t.key -eq "ciphers" )
				     {
                        foreach( $t2 in $t.table )
                        {
						
					       $isweak = ""
						   $csuite = ""
                           foreach( $e in $t2.elem )
						   {				   
						      if( $e.key -eq "strength" )
						      {
						         $isweak = $e.InnerXML
						      }
						      elseif( $e.key -eq "name")
						      {
						         $csuite = $e.InnerXML
						      }
						   }				        
						   
                           if( $isweak -eq "weak" )
                           {
						      $cipher_suite_bad["$SSLTLS_version"] += "$csuite" + " "
						   }
						   else
						   {
						      $cipher_suite_good["$SSLTLS_version"] += "$csuite" + " "
						   }
                        }					 
				     }
                  }
			   }
               $cipher_suite_weak = $scr.elem.InnerXML			   
			}
		 }
		 
		 if ( $subject_common_name -eq $issuer_common_name )
		 {
		    $self_signed = "true"
		 }	 
	  }
	  else
	  {
	     # ERROR  HANDLING
	  }
	  
	  $str_out = "$str_date" + "," + "$str_region" + "," + "$host_ip" + "," + "$host_name" + "," + "$SSLTLS_hit"
	  if( $SSLTLS_hit -eq "true" )
	  {
	     
 	     # $str_headline = "Host IP, Hostname, SSLTLS-hit, HTML Title, SubjectCN, IssuerCN, Selfsigned, CertKeyType, KeyBits, ValidFrom, ValidTo, WeakCipherSuite"
	     $str_out += "," + "$html_title" + "," + "$subject_common_name" + "," + "$issuer_common_name" + "," + "$self_signed" + "," + "$cert_key_type" + "," + "$cert_key_bits" + "," + "$cert_not_before" + "," + "$cert_not_after" + "," + "$cipher_suite_weak"
	     foreach ( $item in $SSLTLSVer )
	     {
		    $str_tmp = $SSLTLS_supported["$item"]
		    $str_out += "," + "$str_tmp"
	     }
		 $str_out >> $csv_filename
	  }
      elseif( $host_name -eq $null )
	  {
	  }
	  else
      {
		 $str_out >> $csv_filename
      }	  
   }
   # break
}