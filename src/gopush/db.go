package gopush

import (
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"

	_ "code.google.com/p/go-mysql-driver/mysql"
)

func (svc *GoPushService) getConnection() *sql.DB {
	if svc.connection == nil {
		var err error
		svc.connection, err = sql.Open("mysql",
			svc.config["dbuser"] + ":" + svc.config["dbpass"] + "@/" + svc.config["dbname"] + "?charset=utf8")
		if err != nil {
			return nil
		}
	}

	return svc.connection
}

func (svc *GoPushService) getPrivateKeyForMailAddress(mail string) *rsa.PrivateKey {
	c := svc.getConnection()
	row := c.QueryRow("SELECT PrivateKey FROM APIToken WHERE Mail = ?", mail)
	var pkey string
	if err := row.Scan(&pkey); err != nil {
		return nil
	}
	
	marshaled, _ := pem.Decode([]byte(pkey))
	prikey, err := x509.ParsePKCS1PrivateKey(marshaled.Bytes)
	if err != nil {
		return nil
	}

	// TODO cache

	return prikey
}
