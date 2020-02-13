package zktcp

import (
	"bufio"
	"fmt"
	"log"
	"net"
)

const (
	host = "127.0.0.1"
	port = "4321"
)

//Init is the function used to initialize the tcp server.
func Init() (err error) {
	var shouldExit bool
	address := host + ":" + port
	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatal("Error when intiaializing tcp server error:", err)
	} else {
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
	response := fmt.Sprintln(clientAddr, "says:", message)

	log.Println(response)

	conn.Write([]byte(fmt.Sprintln("Server Replied: ", response)))

	handleConnection(conn)
}
