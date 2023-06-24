package contract

import "github.com/smokers10/go-infrastructure/config"

type CheckResult struct {
	TableName string
	Mismatch  []string
}

type TableStructureChecker interface {
	StructureChecker(userManagementConfig *config.UserManagementConfig) (result []CheckResult, failure error)
}
