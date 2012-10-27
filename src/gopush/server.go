package gopush

import (
	"io"
	"io/ioutil"
	"net/http"
)

func serve404(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	io.WriteString(w, "Not Found")
}

func serve401(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; chatset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	io.WriteString(w, "Unauthorized")
}

func serveError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusInternalServerError)
	io.WriteString(w, "Internal Server Error")
	io.WriteString(w, "\n")
	io.WriteString(w, err.Error())
}

func (svc *GoPushService) handleTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		serve404(w)
		return
	}

	body, _ := ioutil.ReadAll(r.Body)
	if !svc.checkAuth(r, body) {
		serve401(w)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	w.Write(body)
}
