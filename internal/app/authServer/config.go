package authServer

import "github.com/MrUndead1996/jwt-auth-serv/internal/dataAccess"

type Config struct {
	Port string
	LogLevel string `toml:"log_level"`
	Database *dataAccess.Config
}

func NewConfig(port string) *Config {
	return &Config{
		Port: port,
		LogLevel: "debug",
		Database: dataAccess.NewConfig(),
	}
}
