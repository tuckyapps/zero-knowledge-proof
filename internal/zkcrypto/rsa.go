package zkcrypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"

	"crypto/rand"
)

const (
	rsaGenBits = 2048
)

//RSAKeyPair holds an RSA key pair and a UUID.
type RSAKeyPair struct {
	ProverKey   *rsa.PrivateKey
	VerifierKey rsa.PublicKey
}

//GetRSAKeyPair returns an RSA key pair, using a rand.Reader
//and the rsaGenBits number of bits.
func GetRSAKeyPair() (keyPair RSAKeyPair) {
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaGenBits)

	if err != nil {
		log.Println("There was an error when getting hash:", err.Error())
	}

	publicKey := privateKey.PublicKey

	keyPair.ProverKey = privateKey
	keyPair.VerifierKey = publicKey

	return keyPair
}

//ExportRsaProverKeyAsPemStr is used to export an rsa prover key as string.
func ExportRsaProverKeyAsPemStr(privkey *rsa.PrivateKey) string {
	privkeyBytes := x509.MarshalPKCS1PrivateKey(privkey)
	privkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privkeyBytes,
		},
	)
	return string(privkeyPem)
}

//ParseRsaProverKeyFromPemStr is used to import an rsa prover key from string.
func ParseRsaProverKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

//ExportRsaVerifierKeyAsPemStr is used to export an rsa verifier key as string.
func ExportRsaVerifierKeyAsPemStr(pubkey *rsa.PublicKey) (string, error) {
	pubkeyBytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", err
	}
	pubkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkeyBytes,
		},
	)

	return string(pubkeyPem), nil
}

//ParseRsaVerifierKeyFromPemStr is used to import an rsa verifier key from string.
func ParseRsaVerifierKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break // fall through
	}
	return nil, errors.New("Key type is not RSA")
}
