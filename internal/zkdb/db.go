package zkdb

import (
	"crypto/rsa"
	"errors"
	"log"

	"github.com/gofrs/uuid"
)

//DB represents secrets repository interface
type DB interface {
	InsertNewRow(newRow TableRow) (insertedRow TableRow, err error)
	GetRowByUUID(uuid string) (returnedRow TableRow, err error)
	DeleteRow(uuid string) (result bool, err error)
	UpdateSecret(uuid string, secret string) (modifiedRow TableRow, err error)
}

//MemoryDB is used to store a secrets repository in memory.
type MemoryDB struct {
	table map[string]TableRow
}

//TableRow represents a DB table row.
type TableRow struct {
	UUID         string
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

//Init inits the memory db.
func (mdb MemoryDB) Init() {
	mdb.table = make(map[string]TableRow)
}

//InsertNewRow receives a TableRow and inserts its content in the db.
//In case of success, returns the row, else, returns error.
func (mdb MemoryDB) InsertNewRow(newRow TableRow) (insertedRow TableRow, err error) {
	uuid, err := uuid.NewV4()

	if err != nil {
		log.Println("There was an error when SubmitingSecret:", err.Error())
		return TableRow{}, err
	}
	newRow.UUID = uuid.String()
	newRow.SecretState = awaitingForVerifierSubmission
	mdb.table[newRow.UUID] = newRow

	return newRow, nil
}

//GetRowByUUID receives a UUID string and returns a row if exists.
func (mdb MemoryDB) GetRowByUUID(uuid string) (returnedRow TableRow, err error) {
	if row, doesExist := mdb.table[uuid]; doesExist {
		returnedRow = row
	} else {
		returnedRow = TableRow{}
		err = errors.New("A row for the provided UUID could not be found")
	}
	return returnedRow, err
}

//DeleteRow receives a UUID string and deletes the row if existent.
//Returns true if success or false and error if not.
func (mdb MemoryDB) DeleteRow(uuid string) (result bool, err error) {
	if _, doesExist := mdb.table[uuid]; doesExist {
		delete(mdb.table, uuid)
		result = true
	} else {
		result = false
		err = errors.New("A row for the provided UUID could not be found")
	}
	return result, err
}

//UpdateSecret receives a UUID string and a secret and updates it.
//In case of success, returns the updated row, else, error.
func (mdb MemoryDB) UpdateSecret(uuid string, secret string) (modifiedRow TableRow, err error) {
	if row, doesExist := mdb.table[uuid]; doesExist {
		modifiedRow = row
		modifiedRow.HashedSecret = secret
		mdb.table[uuid] = modifiedRow
	} else {
		modifiedRow = TableRow{}
		err = errors.New("A row for the provided UUID could not be found")
	}
	return modifiedRow, err
}
