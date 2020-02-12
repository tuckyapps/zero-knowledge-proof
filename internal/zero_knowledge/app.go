package zeroknowledge

import (
	"crypto/rsa"

	"github.com/tuckyapps/zero-knowledge-proof/internal/zkcrypto"
)

//TableRow represents a DB table row.
type TableRow struct {
	HashedSecret string
	VerifierKey  rsa.PublicKey
	ProverKey    *rsa.PrivateKey
	SecretState  SecretState
}

//SecretState is the enum used to hold the secret state.
type SecretState int

const (
	match SecretState = 1 + iota
	noMatch
	awaitingForVerifierSubmission
)

//SubmitSecret receives a secret by the prover, store it in the database,
//and returns a keypair with his private key
//and the public key the verifier must use to verify a secret.
func SubmitSecret(secret string) (keyPair zkcrypto.RSAKeyPair) {

}

//VerifySecret receives a secret and a verifier key,
//checks if the secret is the same as the one stored for that verifier key.
//If the secret is the same, stores in database true and returns, in the opposite case,
//stores and returns false.
func VerifySecret(secret string, verifierKey rsa.PublicKey) (doSecretsMatch bool) {

}

//GetSecretState receives a private key from the prover and
//returns if the secrets match or not, or if still waiting for
//verifier to submit its secret.
func GetSecretState(proverKey *rsa.PrivateKey) (currentState string) {

}
