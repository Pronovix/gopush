package gopush

import (
	"crypto/rsa"
)

type Backend interface {
	GetPublicKey(mail string) *rsa.PublicKey
	GetAll() ([]APIToken, error)
	Add(token *APIToken) error
	Remove(mail string) error
	Stop()
}
