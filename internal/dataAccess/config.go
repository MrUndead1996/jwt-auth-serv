package dataAccess

type Config struct {
	URL string `toml:"database_url"`
}

func NewConfig() *Config {
	return &Config{
		URL: "mongodb+srv://users:ABhG60nB47HjGQzF@jwtauthcluster.lu7by.mongodb.net/<dbname>?retryWrites=true&w=majority",
	}
}
