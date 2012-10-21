package gopush

import (
	"encoding/json"
	"io/ioutil"
)

func readConfig(path string) (map[string]string, error) {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var conf map[string]string

	jerr := json.Unmarshal(content, &conf)

	if jerr != nil {
		return nil, jerr
	}

	return conf, nil
}
