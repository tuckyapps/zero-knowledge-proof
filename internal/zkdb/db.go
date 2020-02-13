package zkdb

import (
	"crypto/rsa"
	"errors"
	"log"

	"github.com/gofrs/uuid"
)

//DB represents secrets repository interface
type DB interface {
	Init() (err error)
	InsertNewRow(newRow TableRow) (insertedRow TableRow, err error)
	GetRowByUUID(uuid string) (returnedRow TableRow, err error)
	DeleteRow(uuid string) (result bool, err error)
	UpdateRow(uuid string, toUpdateRow TableRow) (modifiedRow TableRow, err error)
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
	//Match refers to a matching secret state.
	Match SecretState = 1 + iota

	//NoMatch refers to an unmatching secret state.
	NoMatch

	//AwaitingForVerifierSubmission refers to be waiting for verifier submission.
	AwaitingForVerifierSubmission
)

func (ss SecretState) String() string {
	return [...]string{"Match", "NoMatch", "AwaitingForVerifierSubmission"}[ss]
}

//Init inits the memory db.
func (mdb MemoryDB) Init() (err error) {
	mdb.table = make(map[string]TableRow)
	return nil
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
	newRow.SecretState = AwaitingForVerifierSubmission
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

//UpdateRow receives a UUID string and a row and updates it.
//In case of success, returns the updated row, else, error.
func (mdb MemoryDB) UpdateRow(uuid string, toUpdateRow TableRow) (modifiedRow TableRow, err error) {
	if _, doesExist := mdb.table[uuid]; doesExist {
		mdb.table[uuid] = toUpdateRow
	} else {
		modifiedRow = TableRow{}
		err = errors.New("A row for the provided UUID could not be found")
	}
	return modifiedRow, err
}
