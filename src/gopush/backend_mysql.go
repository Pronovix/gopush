package gopush

import (
	"crypto/rsa"
	"database/sql"

	_ "code.google.com/p/go-mysql-driver/mysql"
)

var userCache = make(map[string]*rsa.PublicKey)

type MySQLBackend struct {
	connection 	*sql.DB
	userCache   map[string]*rsa.PublicKey
	enableCache bool
}

func NewMySQLBackend(config Config) *MySQLBackend {
	var err error
	b := &MySQLBackend{}
	b.userCache = make(map[string]*rsa.PublicKey)
	b.enableCache = config.UserCache
	b.connection, err = sql.Open("mysql",
		config.DBUser + ":" + config.DBPass + "@/" + config.DBName + "?charset=utf8")
	if err != nil {
		return nil
	}

	return b
}

func (b *MySQLBackend) Stop() {
	b.connection.Close()
}

func (b *MySQLBackend) getPublicKeyWithoutCache(mail string) *rsa.PublicKey {
	row := b.connection.QueryRow("SELECT PublicKey FROM APIToken WHERE Mail = ?", mail)
	var pkey string
	if err := row.Scan(&pkey); err != nil {
		return nil
	}

	return stringToPublicKey(pkey)
}

func (b *MySQLBackend) GetPublicKey(mail string) *rsa.PublicKey {
	if b.enableCache {
		if _, ok := b.userCache[mail]; !ok {
			if key := b.getPublicKeyWithoutCache(mail); key != nil {
				b.userCache[mail] = key
			} else {
				return nil
			}
		}

		return b.userCache[mail]
	}

	return b.getPublicKeyWithoutCache(mail)
}

func (b *MySQLBackend) GetAll() ([]APIToken, error) {
	rows, err := b.connection.Query("SELECT Mail, PublicKey, Admin FROM APIToken ORDER BY Mail")
	if err != nil {
		return nil, err
	}

	var at []APIToken

	for rows.Next() {
		var a APIToken
		rows.Scan(&a.Mail, &a.PublicKey, &a.Admin)
		at = append(at, a)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return at, nil
}

func (b *MySQLBackend) Add(t *APIToken) error {
	if _, err := b.connection.Exec("INSERT INTO APIToken(Mail, PublicKey, Admin) VALUES(?,?,?)", t.Mail, t.PublicKey, t.Admin); err != nil {
		return err
	}

	return nil
}

func (b *MySQLBackend) Remove(mail string) error{
	if b.enableCache {
		delete(b.userCache, mail)
	}

	if _, err := b.connection.Exec("DELETE FROM APIToken WHERE Mail = ?", mail); err != nil {
		return err
	}

	return nil
}
