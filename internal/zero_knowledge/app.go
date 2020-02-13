package zeroknowledge

import (
	"crypto/rsa"
	"fmt"
	"log"

	"github.com/tuckyapps/zero-knowledge-proof/internal/zkcrypto"
	"github.com/tuckyapps/zero-knowledge-proof/internal/zkdb"
)

//AuxUUIDKeyPair is just used to hold the data returned when submiting a secret.
type AuxUUIDKeyPair struct {
	UUID        string
	ProverKey   *rsa.PrivateKey
	VerifierKey rsa.PublicKey
}

func (aux AuxUUIDKeyPair) String() string {
	return fmt.Sprint("uuid:", aux.UUID, "proverKey:", aux.ProverKey, "verifierKey:", aux.VerifierKey)
}

var db zkdb.DB

//Init intializes the zero knowledge implementation with the database to be used.
func Init(database zkdb.DB) (err error) {
	err = database.Init()
	db = database
	return err
}

//SubmitSecret receives a secret by the prover, store it in the database,
//and returns a uuid and keypair with prover key
//and the verifier key the verifier must use to verify a secret.
func SubmitSecret(secret string) (auxKeyPair AuxUUIDKeyPair, err error) {
	var newTableRow zkdb.TableRow
	keyPair := zkcrypto.GetRSAKeyPair()
	newTableRow.HashedSecret = zkcrypto.GetSecretHash(secret)
	newTableRow.ProverKey = keyPair.ProverKey
	newTableRow.VerifierKey = keyPair.VerifierKey
	insertedRow, err := db.InsertNewRow(newTableRow)

	if err != nil {
		log.Println("There was an error when SubmitSecret:", err.Error())
		return
	}
	auxKeyPair.UUID = insertedRow.UUID
	auxKeyPair.ProverKey = insertedRow.ProverKey
	auxKeyPair.VerifierKey = insertedRow.VerifierKey

	return auxKeyPair, nil
}

//VerifySecret receives a secret, a uuid and a verifier key,
//checks if the secret is the same as the one stored for that verifier key.
//If the secret is the same, stores in database true and returns, in the opposite case,
//stores and returns false.
func VerifySecret(secret string, uuid string, verifierKey rsa.PublicKey) (doSecretsMatch bool, err error) {
	row, err := db.GetRowByUUID(uuid)

	if err != nil {
		log.Println("There was an error when VerifySecret:", err.Error())
		return false, err
	}

	toVerifyHash := zkcrypto.GetSecretHash(secret)
	if verifierKey == row.VerifierKey {
		if toVerifyHash == row.HashedSecret {
			row.SecretState = zkdb.Match
			doSecretsMatch = true
		} else {
			row.SecretState = zkdb.NoMatch
		}
		db.UpdateRow(uuid, row)
	}

	return doSecretsMatch, nil
}

//GetSecretState receives a uuid and private key from the prover and
//returns if the secrets match or not, or if still waiting for
//verifier to submit its secret.
func GetSecretState(uuid string, proverKey *rsa.PrivateKey) (currentState string, err error) {

	row, err := db.GetRowByUUID(uuid)
	currentState = zkdb.NoMatch.String()

	if err != nil {
		log.Println("There was an error when GetSecretState:", err.Error())
		return
	}

	if proverKey == row.ProverKey {
		currentState = row.SecretState.String()
	}

	return currentState, nil
}
