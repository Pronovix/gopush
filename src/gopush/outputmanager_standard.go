package gopush

import (
	"io"
	"text/template"
)

type StandardOutputManager struct {
	AdminTemplate 		*template.Template
	AdminAddTemplate	*template.Template
}

func NewStandardTemplateStoreInWorkingDir() *StandardOutputManager {
	return NewStandardTemplateStore(".")
}

func NewStandardTemplateStore(path string) *StandardOutputManager {
	return &StandardOutputManager{
		AdminTemplate: template.Must(template.ParseFiles(path + "/admin.html")),
		AdminAddTemplate: template.Must(template.ParseFiles(path + "/adminaddgenprikey.html")),
	}
}

func (m *StandardOutputManager) renderAdminPage(w io.Writer, d *adminPageData) error {
	return m.AdminTemplate.Execute(w, d)
}

func (m *StandardOutputManager) renderAdminAddPage(w io.Writer, d *adminAdd) error {
	return m.AdminAddTemplate.Execute(w, d)
}
