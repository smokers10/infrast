package lib

import (
	"fmt"

	"github.com/smokers10/infrast/contract"
)

func CheckResultLogFormat(results []contract.CheckResult) {
	if len(results) == 0 {
		fmt.Println("TSC result : OK!")
	} else {
		fmt.Printf("TSC Result : your YAML configuration has problem \n")
		for _, v := range results {
			fmt.Printf("table %s configuration :\n", v.TableName)
			for _, v2 := range v.Mismatch {
				fmt.Println(v2)
			}
			fmt.Printf("\n")
		}
	}
}
