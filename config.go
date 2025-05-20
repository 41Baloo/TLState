package TLState

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"strings"
)

var (
	ErrFailedDecodePemCert = errors.New("failed to decode PEM certificate")
	ErrFailedDecodePemKey  = errors.New("failed to decode PEM key")
	ErrUnsupportedKeyType  = errors.New("unsupported private key type")
	ErrSignatureMismatch   = errors.New("certificate and key types do not match")
)

type Config struct {
	ParsedCert      *x509.Certificate
	ParsedKey       crypto.Signer
	SignatureScheme SignatureScheme

	ServerCert        []byte
	ServerKey         []byte
	CertificateRecord []byte

	Ciphers []CipherSuite
}

func ConfigFromFile(certPath, keyPath string) (*Config, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || !strings.Contains(certBlock.Type, "CERTIFICATE") {
		return nil, ErrFailedDecodePemCert
	}

	var keyBlock *pem.Block
	for {
		keyBlock, keyPEM = pem.Decode(keyPEM)
		if keyBlock == nil {
			return nil, ErrFailedDecodePemKey
		}
		if strings.Contains(keyBlock.Type, "PRIVATE KEY") {
			break
		}
	}

	return ConfigFromDER(certBlock.Bytes, keyBlock.Bytes)
}

func ConfigFromDER(serverCert, serverKey []byte) (*Config, error) {
	cert, err := x509.ParseCertificate(serverCert)
	if err != nil {
		return nil, err
	}

	signer, scheme, err := parseAndDetectKeyType(serverKey, cert)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		ParsedCert:      cert,
		ParsedKey:       signer,
		SignatureScheme: scheme,
		ServerCert:      serverCert,
		ServerKey:       serverKey,
		Ciphers:         []CipherSuite{TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256},
	}

	cfg.createCertificateRecord()
	return cfg, nil
}

func parseAndDetectKeyType(der []byte, cert *x509.Certificate) (crypto.Signer, SignatureScheme, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return detectSignerAndScheme(key, cert)
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return detectSignerAndScheme(key, cert)
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return detectSignerAndScheme(key, cert)
	}
	return nil, 0, ErrFailedDecodePemKey
}

func detectSignerAndScheme(key any, cert *x509.Certificate) (crypto.Signer, SignatureScheme, error) {
	switch k := key.(type) {

	case *rsa.PrivateKey:

		/*
			RSASSA-PKCS1-v1_5 [RFC8017] with the corresponding hash algorithm
			as defined in [SHS].  These values refer solely to signatures
			which appear in certificates (see Section 4.4.2.2) and are not
			defined for use in signed TLS handshake messages
		*/

		switch cert.SignatureAlgorithm {
		case x509.SHA384WithRSA, x509.SHA384WithRSAPSS:
			return k, RSA_PSS_RSAE_SHA384, nil
		case x509.SHA512WithRSA, x509.SHA512WithRSAPSS:
			return k, RSA_PSS_RSAE_SHA512, nil
		default:
			return k, RSA_PSS_RSAE_SHA256, nil
		}
	case *ecdsa.PrivateKey:
		switch cert.SignatureAlgorithm {
		case x509.ECDSAWithSHA256:
			return k, ECDSA_SECP256R1_SHA256, nil
		case x509.ECDSAWithSHA384:
			return k, ECDSA_SECP384R1_SHA384, nil
		case x509.ECDSAWithSHA512:
			return k, ECDSA_SECP521R1_SHA512, nil
		}
	case ed25519.PrivateKey:
		if cert.SignatureAlgorithm == x509.PureEd25519 {
			return k, ED25519, nil
		}
	}
	return nil, 0, ErrUnsupportedKeyType
}

func (c *Config) createCertificateRecord() {
	certMsg := []byte{
		0x00,
	}

	certLen := 3 + len(c.ServerCert) + 2

	certMsg = append(certMsg,
		byte(certLen>>16),
		byte(certLen>>8),
		byte(certLen))

	certMsg = append(certMsg,
		byte(len(c.ServerCert)>>16),
		byte(len(c.ServerCert)>>8),
		byte(len(c.ServerCert)))
	certMsg = append(certMsg, c.ServerCert...)

	certMsg = append(certMsg, 0x00, 0x00)

	c.CertificateRecord = certMsg
}
