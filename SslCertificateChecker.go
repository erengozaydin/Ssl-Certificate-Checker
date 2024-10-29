package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

func main() {
	fmt.Print("Enter the domain (e.g., example.com): ")
	var domain string
	fmt.Scanln(&domain)
	url := "https://" + domain
	err := getCertificateInfo(url)
	if err != nil {
		log.Fatalf("Error getting certificate info: %v", err)
	}
}

func getCertificateInfo(url string) error {
	// HTTP connection
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %v", err)
	}
	defer resp.Body.Close()

	// Get the TLS connection state
	tlsConnectionState := resp.TLS
	if tlsConnectionState == nil {
		return fmt.Errorf("TLS handshake failed, site might not use HTTPS")
	}

	// Get the first (main) certificate
	certificate := tlsConnectionState.PeerCertificates[0]

	fmt.Println("\n--- Certificate Information ---")
	fmt.Printf("| %-20s | %s\n", "Issuer", certificate.Issuer)
	fmt.Printf("| %-20s | %s\n", "Subject", certificate.Subject)
	fmt.Printf("| %-20s | %s\n", "Not Before", certificate.NotBefore.Format(time.RFC1123))
	fmt.Printf("| %-20s | %s\n", "Not After", certificate.NotAfter.Format(time.RFC1123))
	fmt.Printf("| %-20s | %v\n", "DNS Names", certificate.DNSNames)
	fmt.Printf("| %-20s | %s\n", "Signature Algorithm", certificate.SignatureAlgorithm)
	fmt.Printf("| %-20s | %s\n", "Public Key Algorithm", certificate.PublicKeyAlgorithm)

	// Check certificate expiration
	timeRemaining := time.Until(certificate.NotAfter)
	fmt.Printf("| %-20s | %v\n", "Time remaining", timeRemaining)
	if timeRemaining < 30*24*time.Hour {
		fmt.Println("| Warning | Certificate expires in less than 30 days!")
	}

	// Print the certificate in PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	fmt.Printf("\nCertificate in PEM format:\n%s\n", certPEM)

	fmt.Println("\n--- Vulnerabilities Check ---")
	// Check for weak signature algorithms
	if certificate.SignatureAlgorithm == x509.MD5WithRSA || certificate.SignatureAlgorithm == x509.SHA1WithRSA {
		fmt.Println("| Warning | The certificate uses a weak signature algorithm (MD5 or SHA-1). This may be vulnerable to attacks.")
	}

	// Check for POODLE vulnerability
	for _, proto := range tlsConnectionState.VerifiedChains[0] {
		if strings.Contains(strings.ToLower(proto.SignatureAlgorithm.String()), "ssl") {
			fmt.Println("| Warning | The server might support SSLv3, which is vulnerable to POODLE attack.")
		}
	}

	// Check for weak protocols susceptible to MITM attacks
	for _, version := range tlsConnectionState.PeerCertificates {
		if version.SignatureAlgorithm == x509.SHA1WithRSA || version.SignatureAlgorithm == x509.MD5WithRSA {
			fmt.Println("| Warning | The server uses a weak protocol, making it susceptible to MITM attacks.")
		}
	}

	fmt.Println("\n--- Name Servers and DNSSEC ---")
	// Check name servers and DNSSEC
	host := strings.TrimPrefix(url, "https://")
	nsRecords, err := net.LookupNS(host)
	if err != nil {
		fmt.Printf("| Error | Error looking up name servers: %v\n", err)
	} else {
		fmt.Printf("| Name Servers | %v\n", nsRecords)
	}

	dnssecSupported, _ := net.LookupTXT("_dnssec." + host)
	if len(dnssecSupported) > 0 {
		fmt.Println("| DNSSEC | Supported")
	} else {
		fmt.Println("| DNSSEC | Not Supported")
	}

	fmt.Println("\n--- CAA Records ---")
	// Check CAA records
	caaRecords, err := net.LookupTXT("_caa." + host)
	if err != nil {
		fmt.Printf("| Error | Error looking up CAA records: %v\n", err)
	} else if len(caaRecords) > 0 {
		fmt.Printf("| CAA Records | %v\n", caaRecords)
	} else {
		fmt.Println("| CAA Records | None")
	}

	fmt.Println("\n--- SPF and DMARC ---")
	// Check SPF and DMARC
	spfRecords, _ := net.LookupTXT(host)
	spfRecordFound := false
	for _, record := range spfRecords {
		if strings.HasPrefix(record, "v=spf1") {
			fmt.Printf("| SPF Record | %v\n", record)
			spfRecordFound = true
		}
	}
	if !spfRecordFound {
		fmt.Println("| SPF Record | None")
	}
	dmarcRecords, _ := net.LookupTXT("_dmarc." + host)
	if len(dmarcRecords) > 0 {
		fmt.Printf("| DMARC Record | %v\n", dmarcRecords)
	} else {
		fmt.Println("| DMARC Record | None")
	}

	fmt.Println("\n--- OCSP Check ---")
	// Check OCSP
	for _, ocspURL := range certificate.OCSPServer {
		fmt.Printf("| OCSP Server | %s\n", ocspURL)
	}

	fmt.Println("\n--- CRL Distribution Points ---")
	// Check CRL
	for _, crlURL := range certificate.CRLDistributionPoints {
		fmt.Printf("| CRL Distribution Point | %s\n", crlURL)
	}

	fmt.Println("\n--- Key Length Check ---")
	// Check key length
	if rsaKey, ok := certificate.PublicKey.(*rsa.PublicKey); ok {
		keyLength := rsaKey.Size() * 8
		fmt.Printf("| Key Length | %d bits\n", keyLength)
		if keyLength < 2048 {
			fmt.Println("| Warning | Key length is less than 2048 bits, which is considered insecure.")
		}
	}

	fmt.Println("\n--- TLS Version Check ---")
	// Check TLS version
	if tlsConnectionState.Version < tls.VersionTLS12 {
		fmt.Printf("| Warning | TLS version is %s, which is considered insecure. Please use TLS 1.2 or higher.\n", tls.VersionName(tlsConnectionState.Version))
	} else {
		fmt.Printf("| TLS Version | %s\n", tls.VersionName(tlsConnectionState.Version))
	}

	fmt.Println("\n--- HTTP Security Headers ---")
	// Check HTTP security headers
	headers := resp.Header
	// Check pinning
	if hpkp, ok := headers["Public-Key-Pins"]; ok {
		fmt.Printf("| Public-Key-Pins | %v\n", hpkp)
	} else {
		fmt.Println("| Public-Key-Pins | Not Set")
	}
	if hsts, ok := headers["Strict-Transport-Security"]; ok {
		fmt.Printf("| HSTS | %v\n", hsts)
	} else {
		fmt.Println("| HSTS | Not Set")
	}
	if csp, ok := headers["Content-Security-Policy"]; ok {
		fmt.Printf("| Content-Security-Policy | %v\n", csp)
	} else {
		fmt.Println("| Content-Security-Policy | Not Set")
	}
	if xfo, ok := headers["X-Frame-Options"]; ok {
		fmt.Printf("| X-Frame-Options | %v\n", xfo)
	} else {
		fmt.Println("| X-Frame-Options | Not Set")
	}
	if xcto, ok := headers["X-Content-Type-Options"]; ok {
		fmt.Printf("| X-Content-Type-Options | %v\n", xcto)
	} else {
		fmt.Println("| X-Content-Type-Options | Not Set")
	}
	if setCookie, ok := headers["Set-Cookie"]; ok {
		for _, cookie := range setCookie {
			if strings.Contains(cookie, "Secure") {
				fmt.Println("| Set-Cookie | Secure flag is set")
			} else {
				fmt.Println("| Set-Cookie | Secure flag is NOT set")
			}
			if strings.Contains(cookie, "HttpOnly") {
				fmt.Println("| Set-Cookie | HttpOnly flag is set")
			} else {
				fmt.Println("| Set-Cookie | HttpOnly flag is NOT set")
			}
			if strings.Contains(cookie, "SameSite") {
				fmt.Println("| Set-Cookie | SameSite flag is set")
			} else {
				fmt.Println("| Set-Cookie | SameSite flag is NOT set")
			}
		}
	} else {
		fmt.Println("| Set-Cookie | Not Set")
	}

	fmt.Println("\n--- Weak Cipher Suite Check ---")
	// Check weak cipher suites
	cipherSuite := tlsConnectionState.CipherSuite
	cipherName := tls.CipherSuiteName(cipherSuite)
	if strings.Contains(cipherName, "RC4") || strings.Contains(cipherName, "3DES") {
		fmt.Printf("| Warning | Weak cipher suite detected: %s\n", cipherName)
	} else {
		fmt.Println("| Weak Cipher Suite | None Detected")
	}

	fmt.Println("\n--- Forward Secrecy (FS) Check ---")
	// Check forward secrecy
	if strings.Contains(cipherName, "ECDHE") {
		fmt.Println("| Forward Secrecy | Supported")
	} else {
		fmt.Println("| Forward Secrecy | Not Supported")
	}

	return nil
}
