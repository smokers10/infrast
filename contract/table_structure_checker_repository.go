package contract

import (
	"github.com/stretchr/testify/mock"
)

type Column struct {
	Field string
	Type  string
}

type TableStructureCheckerRepository interface {
	StructureGetter(tablename string, is_user_storage bool) (columns []Column, failure error)
}

type TableStructureCheckerRepositoryMock struct {
	Mock mock.Mock
}

func (m *TableStructureCheckerRepositoryMock) StructureGetter(tablename string, is_user_storage bool) (columns []Column, failure error) {
	args := m.Mock.Called(tablename, is_user_storage)
	return args.Get(0).([]Column), args.Error(1)
}
