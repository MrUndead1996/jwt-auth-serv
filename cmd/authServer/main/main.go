package main

import (
	"flag"
	"github.com/BurntSushi/toml"
	"github.com/MrUndead1996/jwt-auth-serv/internal/app/authServer"
	"log"
	"os"
)

var (
	configPath string
)

func init() {
	flag.StringVar(&configPath,"config-path","configs/authServer.toml", "path to server config file")
}

func main() {
	port := os.Getenv("PORT")
	flag.Parse()
	config := authServer.NewConfig(port)
	_, err := toml.DecodeFile(configPath, config)
	if err != nil {
		log.Fatal(err)
	}
	s := authServer.New(config)
	if err := s.Start(); err != nil {
		log.Fatal(err)
	}
}
