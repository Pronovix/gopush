package gopush

import (
	"io"
)

type adminAdd struct {
	Mail 	string
	Key 	string
}

type adminPageData struct {
	APITokens 	[]APIToken
	Nonce 		string
	FormID		string
}

type OutputManager interface {
	renderAdminPage(io.Writer, *adminPageData) error
	renderAdminAddPage(io.Writer, *adminAdd) error
}
