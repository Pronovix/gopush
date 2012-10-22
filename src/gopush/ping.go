package gopush

import (
	"encoding/json"
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
	center := v.Get("center")
	callback := v.Get("callback") // For JSONP


	if _, ok := svc.lastState[center]; center == "" || !ok {
		serve404(w)
		return
	}

	if callback == "" { // Normal response
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, svc.lastState[center])
	} else { // JSONP response
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		marshaled, _ := json.Marshal(svc.lastState[center])
		io.WriteString(w, callback + "(" + string(marshaled) + ");")
	}
}
