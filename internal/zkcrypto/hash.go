package zkcrypto

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

//CompareSecretAndHash returns true if they match or false if they do not.
func CompareSecretAndHash(secret string, hash string) (result bool) {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(secret))
	if err == nil {
		result = true
	}
	return
}
