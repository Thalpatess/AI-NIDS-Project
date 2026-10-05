package main

import (
	"log"
	"os"

	"github.com/Thalpatess/AI-NIDS-Project/internal/api"
)

func main() {
	addr := os.Getenv("NIDS_API_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	if err := api.StartServer(addr); err != nil {
		log.Fatalf("api server failed: %v", err)
	}
}