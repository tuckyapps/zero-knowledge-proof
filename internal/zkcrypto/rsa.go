package zkcrypto

import (
	"crypto/rsa"
	"log"

	"crypto/rand"
)

const (
	rsaGenBits = 2048
)

//RSAKeyPair holds an RSA key pair.
type RSAKeyPair struct {
	proverKey   *rsa.PrivateKey
	verifierKey rsa.PublicKey
}

//GetRSAKeyPair returns an RSA key pair, using a rand.Reader
//and the rsaGenBits number of bits.
func GetRSAKeyPair() (keyPair RSAKeyPair) {
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaGenBits)

	if err != nil {
		log.Println("There was an error when getting hash:", err.Error())
	}

	publicKey := privateKey.PublicKey

	keyPair.proverKey = privateKey
	keyPair.verifierKey = publicKey

	return keyPair
}
