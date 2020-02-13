package zktcp

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"

	zeroknowledge "github.com/tuckyapps/zero-knowledge-proof/internal/zero_knowledge"
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
		Description: "Returns the info of the available commands.",
	},
	{
		Name:        "submitsecret",
		Description: "Receives a secret by the prover and returns uuid with prover and verifier keys to perform other operations. Example: submitsecret:::secret.",
	},
	{
		Name:        "verifysecret",
		Description: "Receives a secret, a uuid and a verifier key, and returns whether the secrets match or not. Example: verifysecret:::secret:::uuid:::verifierkey.",
	},
	{
		Name:        "getsecretstate",
		Description: "Receives a uuid and a prover key, and returns wheter the secrets match, not match, or if still missing for verifier submission. Example: getsecretstate:::uuid:::proverkey",
	},
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
	clientAddr := conn.RemoteAddr().String()

	if err != nil {
		log.Println(fmt.Sprintln("The client ", clientAddr, " has left.."))
		conn.Close()
		return
	}

	message := string(bufferBytes)
	log.Println(clientAddr, " says: ", message)

	response, err := handleCommand(message)
	if err != nil {
		response = err.Error()
	}

	conn.Write([]byte(fmt.Sprintln("Server", conn.LocalAddr(), "replied:", response, "\n")))

	handleConnection(conn)
}

func handleCommand(message string) (response string, err error) {
	var command string
	message = message[:len(message)-1]

	if message != "help" {
		command = strings.Split(message, commandSeparator)[0]
	} else {
		command = "help"
	}

	switch command {
	case "help":
		response = helpCommand()
	case "submitsecret":
		response, err = submitSecretCommand(message)
	case "verifysecret":
		response, err = verifySecretCommand(message)
	case "getsecretstate":
		response, err = getSecretStateCommand(message)
	default:
		response = "Unrecognized command..." + helpCommand()
	}
	return
}

func helpCommand() (response string) {
	response = "\nAVAILABLE COMMANDS\n"
	for _, command := range commands {
		response += fmt.Sprintf("Name: %s | Description: %s\n", command.Name, command.Description)
	}
	return response[:len(response)-1]
}

func submitSecretCommand(message string) (response string, err error) {
	err = validateMessageHasEnoughParameters(message, 2)
	if err != nil {
		return
	}

	secret := strings.Split(message, commandSeparator)[1]
	auxKeyPair, err := zeroknowledge.SubmitSecret(secret)

	if err != nil {
		return
	}
	return auxKeyPair.String(), nil
}

func verifySecretCommand(message string) (response string, err error) {
	err = validateMessageHasEnoughParameters(message, 4)
	if err != nil {
		return err.Error(), err
	}

	response = "No Match"
	parsedMessage := strings.Split(message, commandSeparator)
	secret := parsedMessage[1]
	uuid := parsedMessage[2]
	verifierKey := parsedMessage[3]
	if err != nil {
		return
	}

	doSecretsMatch, err := zeroknowledge.VerifySecret(secret, uuid, verifierKey)
	if err != nil {
		return
	}

	if doSecretsMatch {
		response = "Match"
	}

	return

}

func getSecretStateCommand(message string) (response string, err error) {
	err = validateMessageHasEnoughParameters(message, 3)
	if err != nil {
		return err.Error(), err
	}

	response = "No Match"
	parsedMessage := strings.Split(message, commandSeparator)
	uuid := parsedMessage[1]
	proverKey := parsedMessage[2]
	if err != nil {
		return
	}

	response, err = zeroknowledge.GetSecretState(uuid, proverKey)
	if err != nil {
		return
	}

	return
}

func validateMessageHasEnoughParameters(message string, minParamenters int) (err error) {
	parsedMessage := strings.Split(message, commandSeparator)
	if len(parsedMessage) < minParamenters {
		err = errors.New("Message does not have enough paramenters")
	}
	return
}
