package gopush

import (
	"encoding/json"
	"io/ioutil"
)

type Config struct {
	Address          string
	DBName           string
	DBUser           string
	DBPass           string
	CertFile         string
	KeyFile          string
	AdminUser        string
	AdminPass        string
	Timeout          int64
	UserCache        bool
	BroadcastBuffer  int64
	ExtraLogging     bool
	RedirectMainPage string
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
