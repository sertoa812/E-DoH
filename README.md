[![Build Status](https://travis-ci.org/miekg/dns.svg?branch=master)](https://travis-ci.org/miekg/dns)
[![Code Coverage](https://img.shields.io/codecov/c/github/miekg/dns/master.svg)](https://codecov.io/github/miekg/dns?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/miekg/dns)](https://goreportcard.com/report/miekg/dns)
[![](https://godoc.org/github.com/miekg/dns?status.svg)](https://godoc.org/github.com/miekg/dns)

# Efficient Detection for DoH service

This tool can achieve rapid discovery of DoH services. Compared to tools such as nmap, it can reduce detection traffic by about 90% and improve detection time efficiency by 80%.


# Usage

-m Max Rountine Number  
-p Use the Path indicator for DoH path enumeration  
-i Specify the input file. Must Required  
-o Specify the output file. Must Required  
-b Base Domain. Must Required.  
-d Debug flag. Disable the debug mode.  
-s Disable the SSL Layer filtration.  
-c Disable the Cert Save flag.  

# Output

This tool outputs three files

## doh.csv
"domain_name", "query",
"ttl", "class", "type", "value", "ID", "RCode", "OPCode", "Authoritative", "AuthenticatedData",
"RecursionAvailable", "RecursionDesired", "Response", "Truncated", "CheckingDisabled"
## ssl.csv
"domain_name", "version",
"cipher", "alpn", "sni", "subject_commonName", "subject_country",
"subject_organization",
"issuerCommonName", "extension_AltNames", "extension_emailAddress", "check_passed"
## log.csv
"ip", "host", "status", "level", "path", "protocol",
"error", "duration"