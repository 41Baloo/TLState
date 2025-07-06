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

type Certificate struct {
	parsedCert *x509.Certificate
	parsedKey  crypto.Signer

	signatureSchemes []SignatureScheme

	certificate       []byte
	certificateRecord []byte
}

func (c *Certificate) SetSchemes(schemes []SignatureScheme) {
	c.signatureSchemes = schemes
}

func (c *Certificate) GetSchemes() []SignatureScheme {
	return c.signatureSchemes
}

func (c *Certificate) createCertificateRecord() {
	certMsg := []byte{
		0x00,
	}

	certLen := 3 + len(c.certificate) + 2

	certMsg = append(certMsg,
		byte(certLen>>16),
		byte(certLen>>8),
		byte(certLen))

	certificateLen := len(c.certificate)

	certMsg = append(certMsg,
		byte(certificateLen>>16),
		byte(certificateLen>>8),
		byte(certificateLen))
	certMsg = append(certMsg, c.certificate...)

	certMsg = append(certMsg, 0x00, 0x00)

	c.certificateRecord = certMsg
}

func CreateCertificateFromFile(certPath, keyPath string) (*Certificate, error) {
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

	return CreateCertificateFromDER(certBlock.Bytes, keyBlock.Bytes)

}

func CreateCertificateFromDER(serverCert, serverKey []byte) (*Certificate, error) {
	cert, err := x509.ParseCertificate(serverCert)
	if err != nil {
		return nil, err
	}

	signer, scheme, err := parseAndDetectKeyType(serverKey)
	if err != nil {
		return nil, err
	}

	certificate := &Certificate{
		parsedCert: cert,
		parsedKey:  signer,

		signatureSchemes: scheme,

		certificate: serverCert,
	}

	certificate.createCertificateRecord()

	return certificate, nil
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

type AlertCallback func(level AlertLevel, description AlertDescription)

type Config struct {
	sniNameToIndex map[string]uint32 // For performance we map each name to an index, so the state does not have to copy the name bytes
	certificates   []*Certificate    // Holds every added certificate

	ciphers     []CipherSuite
	namedGroups []NamedGroup

	alertCallback AlertCallback

	sni         bool
	initialised bool
}

func NewConfig(certificate *Certificate) *Config {
	cfg := Config{
		sniNameToIndex: map[string]uint32{},
		certificates:   []*Certificate{},

		ciphers:     []CipherSuite{TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_256_GCM_SHA384},
		namedGroups: []NamedGroup{NamedGroupX25519, NamedGroupP256},

		sni:         false,
		initialised: certificate != nil,
	}

	if certificate != nil {
		cfg.certificates = append(cfg.certificates, certificate)
	}

	return &cfg
}

// The given function gets called with every received alert
func (c *Config) SetAlertCallback(callback AlertCallback) {
	c.alertCallback = callback
}

// Overwrites the first added certificate
func (c *Config) SetCertificate(certificate *Certificate) {
	c.certificates[0] = certificate
	c.initialised = certificate != nil
}

func (c *Config) GetCertificate() *Certificate {
	return c.certificates[0]
}

func (c *Config) AddSNICertificate(domain string, certificate *Certificate) {
	index := len(c.certificates)
	c.certificates = append(c.certificates, certificate)

	c.sniNameToIndex[domain] = uint32(index)

	c.sni = true
	c.initialised = c.certificates[0] != nil
}

func (c *Config) GetSNICertificateIndexByName(domain string) uint32 {
	return c.sniNameToIndex[domain]
}

func (c *Config) GetCertificateAtIndex(index uint32) *Certificate {
	return c.certificates[index]
}

// (known as "elliptic curves in TLS1.1 & 1.2")
func (c *Config) SetNamedGroups(namedGroups []NamedGroup) {
	c.namedGroups = namedGroups
}

func (c *Config) GetNamedGroups() []NamedGroup {
	return c.namedGroups
}

func (c *Config) SetCiphers(ciphers []CipherSuite) {
	c.ciphers = ciphers
}

func (c *Config) GetCiphers() []CipherSuite {
	return c.ciphers
}
