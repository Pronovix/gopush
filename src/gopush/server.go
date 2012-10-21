package gopush

import (
	"io"
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
