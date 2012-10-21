package gopush

import (
	"net/http"
	"net/url"
)

func (svc *GoPushService) checkAdminAuth(w http.ResponseWriter, r *http.Request) bool {
	if auth := r.Header.Get("Authorization"); auth != "Basic " + svc.adminCreds {
		w.Header().Set("WWW-Authenticate", "Basic realm=\"GoPushNotification admin page\"")
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}

	return true
}

func (svc *GoPushService) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		serve404(w)
		return
	}

	if !svc.checkAdminAuth(w, r) {
		return
	}

	c := svc.getConnection()
	rows, err := c.Query("SELECT Mail, PrivateKey, Admin FROM APIToken ORDER BY Mail")
	if err != nil {
		serveError(w, err)
		return
	}
	var at []APIToken
	for rows.Next() {
		var a APIToken
		rows.Scan(&a.Mail, &a.PrivateKey, &a.Admin)
		at = append(at, a)
	}
	if err := rows.Err(); err != nil {
		serveError(w, err)
		return
	}

	if err := adminPage.Execute(w, at); err != nil {
		serveError(w, err)
		return
	}
}

func (svc *GoPushService) handleAdminAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		serve404(w)
		return
	}

	if !svc.checkAdminAuth(w, r) {
		return
	}

	if err := r.ParseForm(); err != nil {
		serveError(w, err)
		return
	}

	key, errk := svc.genKeyPair()
	if errk != nil {
		serveError(w, errk)
		return
	}

	t := &APIToken{
		Mail: r.FormValue("mail"),
		PrivateKey: key,
		Admin: false,
	}

	c := svc.getConnection()
	if _, err := c.Exec("INSERT INTO APIToken(Mail, PrivateKey, Admin) VALUES(?,?,?)", t.Mail, t.PrivateKey, t.Admin); err != nil {
		serveError(w, err)
		return
	}

	http.Redirect(w, r, "/admin", http.StatusFound)
}

func (svc *GoPushService) handleAdminRemove(w http.ResponseWriter, r *http.Request) {
	if !svc.checkAdminAuth(w, r) {
		return
	}

	v, _ := url.ParseQuery(r.URL.RawQuery)

	mail := v.Get("mail")

	if mail == "" {
		serve404(w)
		return
	}

	c := svc.getConnection()
	if _, err := c.Exec("DELETE FROM APIToken WHERE Mail = ?", mail); err != nil {
		serveError(w, err)
		return
	}

	http.Redirect(w, r, "/admin", http.StatusFound)
}
