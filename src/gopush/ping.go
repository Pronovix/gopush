package gopush

import (
	"io"
	"net/http"
	"net/url"
)

func (svc *GoPushService) handlePing(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		serve404(w)
		return
	}

	v, _ := url.ParseQuery(r.URL.RawQuery)
	id := v.Get("id")

	if _, ok := svc.lastState[id]; id == "" || !ok {
		serve404(w)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, svc.lastState[id])
}
