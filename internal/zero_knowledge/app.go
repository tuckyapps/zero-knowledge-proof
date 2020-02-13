package zeroknowledge

import (
	"crypto/rsa"
	"log"

	"github.com/gofrs/uuid"
	"github.com/tuckyapps/zero-knowledge-proof/internal/zkcrypto"
	"github.com/tuckyapps/zero-knowledge-proof/internal/zkdb"
)

//SubmitSecret receives a secret by the prover, store it in the database,
//and returns a keypair with his private key
//and the public key the verifier must use to verify a secret.
func SubmitSecret(secret string) (keyPair zkcrypto.RSAKeyPair) {
	var newTableRow zkdb.TableRow
	keyPair = zkcrypto.GetRSAKeyPair()
	newTableRow.HashedSecret = zkcrypto.GetSecretHash(secret)
	newTableRow.ProverKey = keyPair.ProverKey
	newTableRow.VerifierKey = keyPair.VerifierKey

	//AddRowToTable
	return keyPair
}

//VerifySecret receives a secret, a uuid and a verifier key,
//checks if the secret is the same as the one stored for that verifier key.
//If the secret is the same, stores in database true and returns, in the opposite case,
//stores and returns false.
func VerifySecret(secret string, uuid string, verifierKey rsa.PublicKey) (doSecretsMatch bool) {
	//hash secret
	//look for hashed secret of verifierkey
	//check if they match
	//store state
	//return result
}

//GetSecretState receives a uuid and private key from the prover and
//returns if the secrets match or not, or if still waiting for
//verifier to submit its secret.
func GetSecretState(uuid string, proverKey *rsa.PrivateKey) (currentState string) {

	//get secret state for proverkey
	//return secret state
}
