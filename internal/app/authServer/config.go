package authServer

import "github.com/MrUndead1996/jwt-auth-serv/internal/dataAccess"

type Config struct {
	Port     string `toml:"host"`
	LogLevel string `toml:"log_level"`
	Database *dataAccess.Config
}

func NewConfig() *Config {
	return &Config{
		Port:     "",
		LogLevel: "debug",
		Database: dataAccess.NewConfig(),
	}
}
