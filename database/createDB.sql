CREATE TABLE CERTFINDINGS(id INT UNSIGNED NOT NULL AUTO_INCREMENT,
                          PRIMARY KEY (id),
                          Date DATETIME,
                          Region VARCHAR(20),
						  Host_IP VARCHAR(20),
						  Hostname VARCHAR(250),
						  HTML_Title VARCHAR(250),
						  SubjectCN VARCHAR(250),
						  IssuerCN VARCHAR(250),
						  Selfsigned BOOL,
						  CertKeyType VARCHAR(20),
						  KeyBits VARCHAR(10),
						  CertSHA1 VARCHAR(50),
						  CertPEM TEXT(1900),
						  ValidFrom DATETIME,
						  ValidTo DATETIME,
						  WeakCipherSuite BOOLEAN,
						  SSLv1 BOOLEAN,
						  SSLv2 BOOLEAN,
						  SSLv3 BOOLEAN,
						  TLSv10 BOOLEAN,
						  TLSv11 BOOLEAN,
						  TLSv12 BOOLEAN,
						  CipherSet TEXT(500))

