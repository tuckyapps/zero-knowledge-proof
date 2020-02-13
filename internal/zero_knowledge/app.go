package zeroknowledge

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/tuckyapps/zero-knowledge-proof/internal/zkcrypto"
	"github.com/tuckyapps/zero-knowledge-proof/internal/zkdb"
	"github.com/tuckyapps/zero-knowledge-proof/internal/zkerror"
)

const (
	maxAttemptsPerHour = 5
)

var db zkdb.DB

//AuxUUIDKeyPair is just used to hold the data returned when submiting a secret.
type AuxUUIDKeyPair struct {
	UUID        string
	ProverKey   string
	VerifierKey string
}

func (aux AuxUUIDKeyPair) String() string {
	return fmt.Sprint("uuid: ", aux.UUID, " proverKey: ", aux.ProverKey, " verifierKey: ", aux.VerifierKey)
}

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
	newTableRow.ProverKey = strings.ReplaceAll(zkcrypto.ExportRsaProverKeyAsPemStr(keyPair.ProverKey), "\n", "")[:200]
	newTableRow.VerifierKey = strings.ReplaceAll(zkcrypto.ExportRsaVerifierKeyAsPemStr(&keyPair.VerifierKey), "\n", "")[:200]
	newTableRow.LastProverAttempt = time.Now()
	newTableRow.LastVerifierAttempt = time.Now()
	insertedRow, err := db.InsertNewRow(newTableRow)

	if err != nil {
		log.Println("There was an error when SubmitSecret:", err.Error())
		return
	}
	auxKeyPair.UUID = insertedRow.UUID
	auxKeyPair.ProverKey = newTableRow.ProverKey
	auxKeyPair.VerifierKey = newTableRow.VerifierKey

	return auxKeyPair, nil
}

//VerifySecret receives a secret, a uuid and a verifier key,
//checks if the secret is the same as the one stored for that verifier key.
//If the secret is the same, stores in database true and returns, in the opposite case,
//stores and returns false.
func VerifySecret(secret string, uuid string, verifierKey string) (doSecretsMatch bool, err error) {
	row, err := db.GetRowByUUID(uuid)
	doSecretsMatch = row.SecretState == zkdb.Match

	if err != nil {
		log.Println("There was an error when VerifySecret:", err.Error())
		return false, err
	}

	err = validateVelocityCheck(row.LastVerifierAttempt, row.VerifierAttemptsCount)

	if err != nil {
		return
	}

	row.LastVerifierAttempt = time.Now()
	if !doSecretsMatch {
		doHashesMatch := zkcrypto.CompareSecretAndHash(secret, row.HashedSecret)
		if verifierKey == row.VerifierKey {
			if doHashesMatch {
				row.SecretState = zkdb.Match
				doSecretsMatch = true
				row.VerifierAttemptsCount = 0
			}
		} else {
			row.VerifierAttemptsCount++
			row.SecretState = zkdb.NoMatch
		}
	}
	db.UpdateRow(uuid, row)

	return doSecretsMatch, nil
}

//GetSecretState receives a uuid and private key from the prover and
//returns if the secrets match or not, or if still waiting for
//verifier to submit its secret.
func GetSecretState(uuid string, proverKey string) (currentState string, err error) {
	row, err := db.GetRowByUUID(uuid)
	currentState = zkdb.NoMatch.String()

	if err != nil {
		log.Println("There was an error when GetSecretState:", err.Error())
		return
	}

	err = validateVelocityCheck(row.LastProverAttempt, row.ProverAttemptsCount)

	if proverKey == row.ProverKey {
		currentState = row.SecretState.String()
		row.ProverAttemptsCount = 0
	} else {
		row.ProverAttemptsCount++

	}
	row.LastProverAttempt = time.Now()
	db.UpdateRow(uuid, row)

	if err != nil {
		return
	}

	return currentState, nil
}

//validateVelocityCheck checks if the user has attempted to perform an operation more than maxAttemptsPerHour in one hour.
func validateVelocityCheck(lastAttempt time.Time, attemptsCount int) (err error) {
	if lastAttempt.Sub(time.Now()).Hours() < 1 && attemptsCount >= maxAttemptsPerHour {
		err = zkerror.ErrUserHasReachedTheMaximumNumberOfAttempts
	}
	return
}
