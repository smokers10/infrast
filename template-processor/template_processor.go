package templateprocessor

import (
	"bytes"
	"html/template"

	"github.com/smokers10/infrast/contract"
)

type templateProcessorImplementation struct{}

// EmailTemplate implements contract.TemplateProcessor
func (i *templateProcessorImplementation) EmailTemplate(data map[string]interface{}, template_path string) (string, error) {
	tmplt, err := template.ParseFiles(template_path)
	if err != nil {
		return "", err
	}

	buf := new(bytes.Buffer)
	if err := tmplt.Execute(buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

func TemplateProccessor() contract.TemplateProcessor {
	return &templateProcessorImplementation{}
}
