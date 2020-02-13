package zktcp

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"

	zeroknowledge "github.com/tuckyapps/zero-knowledge-proof/internal/zero_knowledge"
	"github.com/tuckyapps/zero-knowledge-proof/internal/zkcrypto"
)

const (
	host             = "127.0.0.1"
	port             = "4321"
	commandSeparator = ":::"
)

type command struct {
	Name        string
	Description string
}

var commands = []command{
	{
		Name:        "help",
		Description: "Returns the info of the available commands."},
	{
		Name:        "submitsecret",
		Description: "Receives a secret by the prover and returns uuid with prover and verifier keys to perform other operations. Example: submitsecret:::secret."},
	{
		Name:        "verifysecret",
		Description: "Receives a secret, a uuid and a verifier key, and returns whether the secrets match or not. Example: verifysecret:::secret:::uuid:::verifierkey."},
	{
		Name:        "getsecretstate",
		Description: "Receives a uuid and a prover key, and returns wheter the secrets match, not match, or if still missing for verifier submission. Example: getsecretstate:::uuid:::proverkey"},
}

var shouldExit bool

//Init is the function used to initialize the tcp server.
func Init() (err error) {
	address := host + ":" + port
	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatal("Error when intiaializing tcp server error:", err)
	} else {
		log.Println("Accepting connections in " + address)
		for !shouldExit {
			conn, err := listener.Accept()
			if err != nil {
				log.Fatal("Error when accepting tcp connection", err)
			} else {
				go handleConnection(conn)
			}
		}
	}
	return
}

func handleConnection(conn net.Conn) {
	bufferBytes, err := bufio.NewReader(conn).ReadBytes('\n')

	if err != nil {
		log.Println("The client has left..")
		conn.Close()
		return
	}

	message := string(bufferBytes)
	clientAddr := conn.RemoteAddr().String()
	log.Println(clientAddr, "says:", message)

	response := fmt.Sprintln(message)

	conn.Write([]byte(fmt.Sprintln("Server", conn.LocalAddr(), "replied:", response)))

	handleConnection(conn)
}

func submitSecret(message string) (response string, err error) {
	secret := strings.Split(message, commandSeparator)[1]
	auxKeyPair, err := zeroknowledge.SubmitSecret(secret)

	if err != nil {
		return
	}
	return auxKeyPair.String(), nil
}

func verifySecret(message string) (response string, err error) {
	response = "No Match"
	parsedMessage := strings.Split(message, commandSeparator)
	secret := parsedMessage[1]
	uuid := parsedMessage[2]
	verifierKey, err := zkcrypto.ParseRsaVerifierKeyFromPemStr(parsedMessage[3])
	if err != nil {
		return
	}

	doSecretsMatch, err := zeroknowledge.VerifySecret(secret, uuid, *verifierKey)
	if err != nil {
		return
	}

	if doSecretsMatch {
		response = "Match"
	}

	return

}

func getSecretState(message string) (response string, err error) {
	response = "No Match"
	parsedMessage := strings.Split(message, commandSeparator)
	uuid := parsedMessage[1]
	proverKey, err := zkcrypto.ParseRsaProverKeyFromPemStr(parsedMessage[2])
	if err != nil {
		return
	}

	response, err = zeroknowledge.GetSecretState(uuid, proverKey)
	if err != nil {
		return
	}

	return
}
