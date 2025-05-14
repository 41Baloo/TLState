package TLState

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/curve25519"
)

var (
	ErrFailedDecodePemCert = errors.New("failed to decode PEM certificate")
	ErrFailedDecodePemKey  = errors.New("failed to decode PEM key")
)

type Config struct {
	ParsedCert *x509.Certificate
	ParsedKey  *rsa.PrivateKey

	PrivateKey []byte
	PublicKey  []byte

	ServerCert []byte
	ServerKey  []byte

	CertificateRecord []byte

	Ciphers []CipherSuite
}

func ConfigFromFile(cert, key string) (*Config, error) {
	certPEM, err := os.ReadFile(cert)
	if err != nil {
		return nil, err
	}

	keyPEM, err := os.ReadFile(key)
	if err != nil {
		return nil, err
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || !strings.HasSuffix(certBlock.Type, "CERTIFICATE") {
		return nil, ErrFailedDecodePemCert
	}
	certDER := certBlock.Bytes

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || !strings.HasSuffix(keyBlock.Type, "PRIVATE KEY") {
		return nil, ErrFailedDecodePemKey
	}
	keyDER := keyBlock.Bytes

	return ConfigFromDER(certDER, keyDER)
}

func ConfigFromDER(serverCert, serverKey []byte) (*Config, error) {
	privateKey := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, privateKey)
	if err != nil {
		return nil, err
	}

	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(serverCert)
	if err != nil {
		return nil, err
	}

	// try PKCS#1, then PKCS#8, just for compatibility
	var key *rsa.PrivateKey
	if k1, err := x509.ParsePKCS1PrivateKey(serverKey); err == nil {
		key = k1
	} else if k8, err2 := x509.ParsePKCS8PrivateKey(serverKey); err2 == nil {
		rk, ok := k8.(*rsa.PrivateKey)
		if !ok {
			return nil, ErrFailedDecodePemKey
		}
		key = rk
	} else {
		return nil, ErrFailedDecodePemKey
	}

	config := Config{
		ParsedCert: cert,
		ParsedKey:  key,

		PrivateKey: privateKey,
		PublicKey:  publicKey,

		ServerCert: serverCert,
		ServerKey:  serverKey,

		// Technically ChaCha20 would be faster, tho most systems have AES hardware acceleration
		Ciphers: []CipherSuite{TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256},
	}

	config.createGertificateRecord()

	return &config, nil
}

func (c *Config) createGertificateRecord() {

	certMsg := []byte{
		0x00,
	}

	certEntryLen := 3 + len(c.ServerCert) + 2

	certMsg = append(certMsg,
		byte(certEntryLen>>16),
		byte(certEntryLen>>8),
		byte(certEntryLen))

	certMsg = append(certMsg,
		byte(len(c.ServerCert)>>16),
		byte(len(c.ServerCert)>>8),
		byte(len(c.ServerCert)))
	certMsg = append(certMsg, c.ServerCert...)

	certMsg = append(certMsg, 0x00, 0x00)

	c.CertificateRecord = certMsg
}
