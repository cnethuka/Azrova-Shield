package main

import (
	"log"
	"os"

	"azrova-shield/src/config"
	"azrova-shield/src/server"
)

func main() {
	baseDir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	cfg, err := config.Load(baseDir)
	if err != nil {
		log.Fatal(err)
	}
	srv := server.New(cfg)
	log.Fatal(srv.Start())
}