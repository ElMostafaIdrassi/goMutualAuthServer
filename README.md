## goMutualAuthServer

goMutualAuthServer implements a localhost TLS server in Golang, which can be used to perform Mutual Authentication (A.K.A Client-Side Authentication). 

This allows for testing Client-Side Authentication, using certificates in various formats :

- PKCS#11 certificates
- KSP / CSP certificates
- CryptoTokenKit certificates

## Installation

The goMutualAuthServer executable is installable using : `go install github.com/ElMostafaIdrassi/goMutualAuthServer@latest`.

Official releases can also be downloaded from the [Releases](https://github.com/ElMostafaIdrassi/goMutualAuthServer/releases) section.

## Usage

```
goMutualAuthServer (-cert /path/to/server/cert) (-key /path/to/server/key) (-port serverPort) (-tlsVersion version)
  -cert /path/to/server/cert
        Path to server's certificate in PEM format
  -key /path/to/server/key
        Path to server's private key in PEM format
  -port serverPort
        Server port (default is 443)
  -tlsVersion version
        TLS version of the server (default is "1.2", possible values "1.0", "1.1", "1.2", "1.3")
```

If neither of `-cert` and `-key` are set, the TLS server will default to using a default [key](https://raw.githubusercontent.com/ElMostafaIdrassi/goMutualAuthServer/master/tls_server_key.pem) and [certificate](https://raw.githubusercontent.com/ElMostafaIdrassi/goMutualAuthServer/master/tls_server_cert.pem).

Both `-cert` and `-key` must be set to override this behaviour.

Finally, make sure you trust the CA certificate that issued the TLS server certificate to avoid in-browser warnings. If using the default TLS server certificate, its CA can be found [here](https://raw.githubusercontent.com/ElMostafaIdrassi/goMutualAuthServer/master/tls_server_ca.crt).
