package gopush

import (
	"encoding/json"
	"io/ioutil"
)

type Config struct {
	DBName 		string
	DBUser 		string
	DBPass		string
	AdminUser 	string
	AdminPass	string
	Timeout		int64
	UserCache 	bool
}

func ReadConfig(path string) (Config, error) {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	var conf Config

	jerr := json.Unmarshal(content, &conf)

	if jerr != nil {
		return Config{}, jerr
	}

	return conf, nil
}
