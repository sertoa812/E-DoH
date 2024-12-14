package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
)

func saveCertificateAsCRT(file_path string, host string, cert *x509.Certificate) {
	certPEMBlock := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	certPEM := pem.EncodeToMemory(certPEMBlock)

	// Save certificate to a .crt file
	save_file_name := filepath.Join(file_path, host) + ".crt"
	err := ioutil.WriteFile(save_file_name, certPEM, 0644)
	if err != nil {
		fmt.Printf("Failed to save certificate as .crt file: %v \n", err)
	}
}
func extract_information(domain_name string, cert *x509.Certificate,
	sslConn *tls.Conn, check_passed bool) string {

	// ssl information extraction
	state := sslConn.ConnectionState()

	version := sslVersionToString(sslConn.ConnectionState().Version)
	cipher := tls.CipherSuiteName(sslConn.ConnectionState().CipherSuite)
	alpn := state.NegotiatedProtocol
	sni := state.ServerName

	// x509 information extraction
	//subject information
	subject_country := strings.Join(cert.Subject.Country, ",")
	subject_organization := strings.Join(cert.Subject.Organization, ",")
	// subject_organizationalUnit := strings.Join(cert.Subject.OrganizationalUnit, ",")
	// subject_locality := strings.Join(cert.Subject.Locality, ",")
	// subject_province := strings.Join(cert.Subject.Province, ",")
	// subject_streetAddress := strings.Join(cert.Subject.StreetAddress, ",")
	// subject_postalCode := strings.Join(cert.Subject.PostalCode, ",")
	// subject_serialNumber := cert.Subject.SerialNumber
	subject_commonName := cert.Subject.CommonName

	// issuer information
	// issuerCountry := strings.Join(cert.Issuer.Country, ",")
	// issuerOrganization := strings.Join(cert.Issuer.Organization, ",")
	// issuerOrganizationalUnit := strings.Join(cert.Issuer.OrganizationalUnit, ",")
	// issuerLocality := strings.Join(cert.Issuer.Locality, ",")
	// issuerProvince := strings.Join(cert.Issuer.Province, ",")
	// issuerStreetAddress := strings.Join(cert.Issuer.StreetAddress, ",")
	// issuerPostalCode := strings.Join(cert.Issuer.PostalCode, ",")
	// issuerSerialNumber := cert.Issuer.SerialNumber
	issuerCommonName := cert.Issuer.CommonName

	// extensions
	extension_AltNames := strings.Join(cert.DNSNames, ",")
	extension_emailAddress := strings.Join(cert.EmailAddresses, ",")
	var check_string string
	if check_passed {
		check_string = "True"
	} else {
		check_string = "False"
	}
	results := []string{domain_name, version, cipher, alpn, sni,
		subject_commonName, subject_country, subject_organization,
		issuerCommonName, extension_AltNames,
		extension_emailAddress, check_string}
	// results := []string{domain_name, version, cipher, alpn, sni,
	// 	subject_commonName, subject_country, subject_organization,
	// 	issuerCountry, issuerOrganization, issuerCommonName, extension_AltNames,
	// 	extension_emailAddress}

	return strings.TrimSuffix(strings.Join(results, "_@_"), "_@_")

}

// func save_info(data string, save_path string, file_name string) {
// 	filePath := filepath.Join(save_path, file_name) // 文件路径，可以根据实际情况修改

// 	// 打开文件，以追加方式写入数据
// 	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE, 0666)
// 	if err != nil {
// 		fmt.Printf("Failed to open file: %v\n", err)
// 		return
// 	}
// 	defer file.Close()

// 	// 写入新行数据
// 	ssl_header := strings.TrimSuffix(strings.Join([]string{"domain_name", "version",
// 		"cipher", "alpn", "sni", "subject_commonName", "subject_country",
// 		"subject_organization", "subject_organizationalUnit", "subject_locality",
// 		"subject_province,subject_streetAddress", "subject_postalCode",
// 		"subject_serialNumber,issuerCountry", "issuerOrganization",
// 		"issuerOrganizationalUnit", "issuerLocality", "issuerProvince",
// 		"issuerStreetAddress", "issuerPostalCode", "issuerSerialNumber",
// 		"issuerCommonName", "extension_AltNames", "extension_emailAddress", "\n"},
// 		"|"), "|")
// 	doh_header := strings.TrimSuffix(strings.Join([]string{"domain_name", "query",
// 		"ttl", "class", "type", "value", "\n"},
// 		"\t"), "\t")

// 	if file_name == "ssl.csv" {
// 		_, err = file.WriteString(ssl_header)
// 	} else if file_name == "doh_1.csv" || file_name == "doh_2.csv" {
// 		_, err = file.WriteString(doh_header)
// 	}
// 	_, err = file.WriteString(data)
// 	if err != nil {
// 		fmt.Printf("Failed to write data to file: %v\n", err)
// 		return
// 	}

// 	fmt.Println(file_name + " saved successfully.")
// }

// func read_hosts(filePath string) []string {
// 	var lines []string

// 	file, err := os.Open(filePath)
// 	if err != nil {
// 		fmt.Printf("Failed to open file: %v\n", err)
// 		return lines
// 	}
// 	defer file.Close()

// 	scanner := bufio.NewScanner(file)

// 	for scanner.Scan() {
// 		line := scanner.Text()
// 		lines = append(lines, line)
// 	}

// 	// 检查是否有错误发生
// 	if err := scanner.Err(); err != nil {
// 		fmt.Printf("Failed to read file: %v\n", err)
// 		return lines
// 	}
// 	return lines
// }
