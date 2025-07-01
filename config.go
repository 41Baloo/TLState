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
	ErrFailedDecodePemCert   = errors.New("failed to decode PEM certificate")
	ErrFailedDecodePemKey    = errors.New("failed to decode PEM key")
	ErrUnsupportedKeyType    = errors.New("unsupported private key type")
	ErrSignatureMismatch     = errors.New("certificate and key types do not match")
	ErrUnsupportedEcdsaCurve = errors.New("unsupported ecdsa curve")
)

type Config struct {
	parsedCert       *x509.Certificate
	parsedKey        crypto.Signer
	signatureSchemes []SignatureScheme

	serverCert        []byte
	serverKey         []byte
	certificateRecord []byte

	ciphers []CipherSuite
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

	signer, scheme, err := parseAndDetectKeyType(serverKey)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		parsedCert:       cert,
		parsedKey:        signer,
		signatureSchemes: scheme,
		serverCert:       serverCert,
		serverKey:        serverKey,
		ciphers:          []CipherSuite{TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_256_GCM_SHA384},
	}

	cfg.createCertificateRecord()
	return cfg, nil
}

func parseAndDetectKeyType(der []byte) (crypto.Signer, []SignatureScheme, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return detectSignerAndScheme(key)
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return detectSignerAndScheme(key)
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return detectSignerAndScheme(key)
	}
	return nil, nil, ErrFailedDecodePemKey
}

func detectSignerAndScheme(key any) (crypto.Signer, []SignatureScheme, error) {
	switch k := key.(type) {

	case *rsa.PrivateKey:

		/*
			RSASSA-PKCS1-v1_5 [RFC8017] with the corresponding hash algorithm
			as defined in [SHS].  These values refer solely to signatures
			which appear in certificates (see Section 4.4.2.2) and are not
			defined for use in signed TLS handshake messages
		*/

		return k, []SignatureScheme{
			RSA_PSS_RSAE_SHA256, RSA_PSS_RSAE_SHA384, RSA_PSS_RSAE_SHA512,
		}, nil
	case *ecdsa.PrivateKey:
		curve := k.Curve.Params().BitSize
		switch curve {
		case 256:
			return k, []SignatureScheme{ECDSA_SECP256R1_SHA256}, nil
		case 384:
			return k, []SignatureScheme{ECDSA_SECP384R1_SHA384}, nil
		case 521:
			return k, []SignatureScheme{ECDSA_SECP521R1_SHA512}, nil
		default:
			return nil, nil, ErrUnsupportedEcdsaCurve
		}
	case ed25519.PrivateKey:
		return k, []SignatureScheme{ED25519}, nil
	}
	return nil, nil, ErrUnsupportedKeyType
}

func (c *Config) SetCiphers(ciphers []CipherSuite) {
	c.ciphers = ciphers
}

func (c *Config) GetCiphers() []CipherSuite {
	return c.ciphers
}

func (c *Config) SetSchemes(schemes []SignatureScheme) {
	c.signatureSchemes = schemes
}

func (c *Config) GetSchemes() []SignatureScheme {
	return c.signatureSchemes
}

func (c *Config) createCertificateRecord() {
	certMsg := []byte{
		0x00,
	}

	certLen := 3 + len(c.serverCert) + 2

	certMsg = append(certMsg,
		byte(certLen>>16),
		byte(certLen>>8),
		byte(certLen))

	certMsg = append(certMsg,
		byte(len(c.serverCert)>>16),
		byte(len(c.serverCert)>>8),
		byte(len(c.serverCert)))
	certMsg = append(certMsg, c.serverCert...)

	certMsg = append(certMsg, 0x00, 0x00)

	c.certificateRecord = certMsg
}
