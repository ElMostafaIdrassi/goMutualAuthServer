package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/grantae/certinfo"
	"golang.org/x/net/http2"
)

func tlsVersionToString(tlsVersion uint16) string {
	switch tlsVersion {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	case tls.VersionSSL30:
		return "3.0"
	default:
		return "UNKNOWN"
	}
}

func cipherSuiteToString(cipherSuite uint16) string {
	switch cipherSuite {
	case tls.TLS_RSA_WITH_RC4_128_SHA:
		return "TLS_RSA_WITH_RC4_128_SHA"
	case tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:
		return "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_RSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_RSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_RSA_WITH_AES_128_CBC_SHA256:
		return "TLS_RSA_WITH_AES_128_CBC_SHA256"
	case tls.TLS_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:
		return "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:
		return "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
	case tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
	case tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
		return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
	case tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
		return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
	case tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
		return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
	case tls.TLS_AES_128_GCM_SHA256:
		return "TLS_AES_128_GCM_SHA256"
	case tls.TLS_AES_256_GCM_SHA384:
		return "TLS_AES_256_GCM_SHA384"
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return "TLS_CHACHA20_POLY1305_SHA256"
	case tls.TLS_FALLBACK_SCSV:
		return "TLS_FALLBACK_SCSV"
	default:
		return "UNKNOWN"
	}
}

func tlsVersionsToString(tlsVersions []uint16) string {
	output := "["
	for i, tlsVersion := range tlsVersions {
		output += tlsVersionToString(tlsVersion) + "(" + fmt.Sprintf("%d", tlsVersion) + ")"
		if i < len(tlsVersions)-1 {
			output += " "
		}
	}
	output += "]"
	return output
}

func cipherSuitesToString(cipherSuites []uint16) string {
	output := "["
	for i, cipherSuite := range cipherSuites {
		output += cipherSuiteToString(cipherSuite) + "(" + fmt.Sprintf("%d", cipherSuite) + ")"
		if i < len(cipherSuites)-1 {
			output += " "
		}
	}
	output += "]"
	return output
}

func x509ToString(x509 *x509.Certificate) string {
	if x509 == nil {
		return "Unavailable"
	} else {
		str, err := certinfo.CertificateText(x509)
		if err != nil {
			return "Unparsable"
		}
		return str
	}
}

var defaultTlsKeyPEM = "-----BEGIN RSA PRIVATE KEY-----\n" +
	"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\n" +
	"-----END RSA PRIVATE KEY-----\n"

var defaultTlsCertPEM = "-----BEGIN CERTIFICATE-----\n" +
	"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\n" +
	"aUpT228IkSGeJdmSjQ==\n" +
	"-----END CERTIFICATE-----\n"

func main() {

	var cert tls.Certificate
	var err error

	tlsVersion := uint16(tls.VersionTLS10)
	tlsVersionFlag := flag.String("tlsversion", "1.2", "TLS version of the server")
	serverPort := flag.Int("port", 443, "Server port")
	pathToServerKey := flag.String("key", "", "Path to server's private key in PEM format")
	pathToServerCert := flag.String("cert", "", "Path to server's certificate in PEM format")
	flag.Parse()

	switch *tlsVersionFlag {
	case "1.0":
		tlsVersion = tls.VersionTLS10
	case "1.1":
		tlsVersion = tls.VersionTLS11
	case "1.2":
		tlsVersion = tls.VersionTLS12
	case "1.3":
		tlsVersion = tls.VersionTLS13
	default:
		fmt.Printf("ERROR: Value %v for -tlsversion not supported. Possible values are 1.0, 1.1, 1.2 and 1.3.\n", *tlsVersionFlag)
		flag.Usage()
		return
	}
	if *pathToServerCert == "" && *pathToServerKey != "" {
		fmt.Printf("ERROR: If -key is set, -cert must also be set.\n")
		flag.Usage()
		return
	}
	if *pathToServerKey == "" && *pathToServerCert != "" {
		fmt.Printf("ERROR: If -cert is set, -key must also be set.\n")
		flag.Usage()
		return
	}

	if *pathToServerKey == "" || *pathToServerCert == "" {
		cert, err = tls.X509KeyPair([]byte(defaultTlsCertPEM), []byte(defaultTlsKeyPEM))
		if err != nil {
			fmt.Printf("ERROR: tls.X509KeyPair() failed: %s\n", err)
			return
		}
	} else {
		cert, err = tls.LoadX509KeyPair(*pathToServerCert, *pathToServerKey)
		if err != nil {
			fmt.Printf("ERROR: tls.LoadX509KeyPair() failed: %s\n", err)
			return
		}
	}

	config := &tls.Config{
		// Set ClientAuth to require client certificates (or
		// VerifyPeerCertificate will run anyway and panic accessing certs[0])
		// but not verify them with the default verifier.
		ClientAuth: tls.RequireAnyClientCert,

		MinVersion: tlsVersion,
		MaxVersion: tlsVersion,
	}
	config.GetCertificate = func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		fmt.Printf("\n======== ClientHello ========\n")

		fmt.Printf("CipherSuites      : %s\n", cipherSuitesToString(clientHello.CipherSuites))
		fmt.Printf("ServerName        : %s\n", clientHello.ServerName)
		fmt.Printf("SupportedCurves   : %v\n", clientHello.SupportedCurves)
		fmt.Printf("SupportedPoints   : %v\n", clientHello.SupportedPoints)
		fmt.Printf("SignatureSchemes  : %v\n", clientHello.SignatureSchemes)
		fmt.Printf("SupportedProtos   : %v\n", clientHello.SupportedProtos)
		fmt.Printf("SupportedVersions : %s\n\n", tlsVersionsToString(clientHello.SupportedVersions))

		return &cert, nil
	}
	config.VerifyConnection = func(state tls.ConnectionState) error {
		fmt.Printf("\n======== VerifyConnection ========\n")

		fmt.Printf("HandshakeComplete      : %v\n", state.HandshakeComplete)
		fmt.Printf("Version                : %s(%v)\n", tlsVersionToString(state.Version), state.Version)
		fmt.Printf("CipherSuite            : %s(%v)\n\n", cipherSuiteToString(state.CipherSuite), state.CipherSuite)

		return nil
	}
	config.VerifyPeerCertificate = func(certificates [][]byte, _ [][]*x509.Certificate) error {
		fmt.Printf("\n======== VerifyPeerCertificate ========\n")

		certs := make([]*x509.Certificate, len(certificates))
		for i, asn1Data := range certificates {
			cert, err := x509.ParseCertificate(asn1Data)
			if err != nil {
				fmt.Printf("ERROR: x509.ParseCertificate() failed: %s\n\n", err)
				return errors.New("tls: failed to parse certificate from server: " + err.Error())
			}
			certs[i] = cert
		}

		// We accept all certs, so we only verify that we got a client certificate.
		if len(certs) == 0 {
			fmt.Printf("ERROR: No client certificate\n\n")
			return fmt.Errorf("no client certificate")
		}

		fmt.Printf("%s\n\n", x509ToString(certs[0]))
		return nil
	}

	address := "localhost:" + fmt.Sprintf("%d", *serverPort)
	server := &http.Server{
		Addr:      address,
		TLSConfig: config,
	}
	server.ConnState = func(conn net.Conn, state http.ConnState) {
		switch state {
		case http.StateNew:
			fmt.Printf("INFO: Connection State: NEW\n")
		case http.StateActive:
			fmt.Printf("INFO: Connection State: ACTIVE\n")
		case http.StateIdle:
			fmt.Printf("INFO: Connection State: IDLE\n")
		case http.StateHijacked:
			fmt.Printf("INFO: Connection State: HIJACKED\n")
		case http.StateClosed:
			fmt.Printf("INFO: Connection State: CLOSED\n")
		default:
			fmt.Printf("INFO: Connection State: UNKNOWN\n")
		}
		_, ok := conn.(*tls.Conn)
		if ok {
			fmt.Printf("INFO: Connection is TLS\n")
		}
		fmt.Print("\n")
	}
	http2.ConfigureServer(server, nil)
	http.HandleFunc("/", handler)

	fmt.Printf("INFO: Server listening...\n")
	server.ListenAndServeTLS("", "")
}

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text")

	state := r.TLS

	io.WriteString(w, "Connected!\n\n")

	io.WriteString(w, "=========== TLS Connection State ===========\n")
	io.WriteString(w, "HandshakeComplete  : "+fmt.Sprintf("%v", state.HandshakeComplete)+"\n")
	io.WriteString(w, "Version            : "+tlsVersionToString(state.Version)+"("+fmt.Sprintf("%v", state.Version)+")\n")
	io.WriteString(w, "CipherSuite        : "+cipherSuiteToString(state.CipherSuite)+"("+fmt.Sprintf("%v", state.CipherSuite)+")\n")
	io.WriteString(w, "NegotiatedProtocol : "+state.NegotiatedProtocol+"\n\n")

	io.WriteString(w, "=========== Request State ===========\n")
	io.WriteString(w, "Protocol           : "+r.Proto+"\n")
	io.WriteString(w, "Remote             : "+r.RemoteAddr+"\n")
	io.WriteString(w, "RequestURI         : "+r.RequestURI+"\n\n")

	io.WriteString(w, "=========== Peer Certificate ===========\n")
	if len(state.PeerCertificates) > 0 {
		io.WriteString(w, "Subject            : "+state.PeerCertificates[0].Subject.CommonName+"\n")
		io.WriteString(w, "Cert               : "+x509ToString(state.PeerCertificates[0])+"\n\n")
	}
}
