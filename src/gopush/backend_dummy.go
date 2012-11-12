package gopush

import (
	"crypto/rsa"
)

type DummyBackend struct {
	data map[string]string
}

func NewDummyBackend() *DummyBackend {
	return &DummyBackend{
		data: make(map[string]string),
	}
}

func (b *DummyBackend) GetPublicKey(mail string) *rsa.PublicKey {
	if key, ok := b.data[mail]; ok {
		return stringToPublicKey(key)
	}

	return nil
}

func (b *DummyBackend) GetAll() ([]APIToken, error) {
	var at []APIToken

	for mail, key := range b.data {
		at = append(at, APIToken{
			Mail: mail,
			PublicKey: key,
			Admin: false,
		})
	}

	return at, nil
}

func (b *DummyBackend) Add(token *APIToken) error {
	b.data[token.Mail] = token.PublicKey

	return nil
}

func (b *DummyBackend) Remove(mail string) error {
	delete(b.data, mail)

	return nil
}

func (b *DummyBackend) Stop() {
	b.data = nil
}