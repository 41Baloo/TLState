package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	config := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}

	conn, err := tls.Dial("tcp", "localhost:8443", config)
	if err != nil {
		fmt.Println("Error connecting to server:", err)
		return
	}
	defer conn.Close()

	fmt.Println("Connected to server at localhost:8443 using TLS 1.3")
	fmt.Println("Type your messages and press Enter to send. Type 'exit' to quit.")

	go func() {
		buffer := make([]byte, 1024)
		for {
			n, err := conn.Read(buffer)
			if err != nil {
				if err != io.EOF {
					fmt.Println("Error reading from server:", err)
				}
				fmt.Println("Connection closed")
				os.Exit(0)
				return
			}
			fmt.Printf("Server: %s", buffer[:n])
		}
	}()

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		message := scanner.Text()
		if strings.ToLower(message) == "exit" {
			fmt.Println("Exiting...")
			break
		}

		_, err := conn.Write([]byte(message + "\n"))
		if err != nil {
			fmt.Println("Error sending message:", err)
			break
		}
	}
}
