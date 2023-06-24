package lib

import (
	"fmt"

	"github.com/smokers10/go-infrastructure/contract"
)

func CheckResultLogFormat(results []contract.CheckResult) {
	if len(results) == 0 {
		fmt.Println("table property check : OK!")
	} else {
		for _, v := range results {
			fmt.Printf("mismatch property naming on table %s :\n", v.TableName)
			for _, v2 := range v.Mismatch {
				fmt.Println(v2)
			}
		}
	}
}
