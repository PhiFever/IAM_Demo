package main

import (
	"IAM_Demo/server"
)

func main() {
	s := server.NewServer()
	s.SetupRouter()

	if err := s.Start(":8080"); err != nil {
		panic("Failed to start server: " + err.Error())
	}
}
