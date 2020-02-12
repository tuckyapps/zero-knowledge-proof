package crypto

import "golang.org/x/crypto/bcrypt"

import "log"

//GetSecretHash returns a bcrypt hash of a password.
func GetSecretHash(secret string) (hash string) {

	secretBytes := []byte(secret)
	hashedSecretBytes, err := bcrypt.GenerateFromPassword(secretBytes, 10)

	if err != nil {
		log.Println("There was an error when getting hash:", err.Error())
	}

	return string(hashedSecretBytes)
}
