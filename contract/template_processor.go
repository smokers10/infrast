package contract

import "github.com/stretchr/testify/mock"

type TemplateProcessor interface {
	EmailTemplate(data map[string]interface{}, template_path string) (string, error)
}

type TemplateProcessorMock struct {
	Mock mock.Mock
}

func (m *TemplateProcessorMock) EmailTemplate(data map[string]interface{}, template_path string) (string, error) {
	argsMock := m.Mock.Called(data, template_path)
	return argsMock.String(0), argsMock.Error(1)
}
