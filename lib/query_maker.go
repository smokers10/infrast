package lib

import (
	"fmt"
	"strconv"
)

func UserQueryMaker(credentials []string) (selectClause string, whereClause string) {
	for _, str := range credentials {
		whereClause += str + " = $1 OR "
		selectClause += str + ", "
	}
	whereClause = whereClause[:len(whereClause)-5]
	selectClause = selectClause[:len(selectClause)-2]

	return selectClause, whereClause
}

func UserQueryMakerTesting(credentials []string) (selectClause string, whereClause string) {
	for _, str := range credentials {
		whereClause += str + " = \\$1 OR "
		selectClause += str + ", "
	}
	whereClause = whereClause[:len(whereClause)-5]
	selectClause = selectClause[:len(selectClause)-2]

	return selectClause, whereClause
}

func WhereClause(credentials []string, argsPosition string) (whereClause string) {
	for _, str := range credentials {
		whereClause += str + fmt.Sprintf(" = %s OR ", argsPosition)
	}
	whereClause = whereClause[:len(whereClause)-4]

	return whereClause
}

func InsertQueryValueMaker(args ...string) (value string) {
	for _, v := range args {
		_, err := strconv.Atoi(v)
		if err != nil {
			value += fmt.Sprintf("'%s', ", v)
		} else {
			isPhone, _ := PhoneChecker(v)
			if isPhone {
				value += fmt.Sprintf("'%s', ", v)
			} else {
				value += fmt.Sprintf("%s, ", v)
			}
		}
	}
	value = value[:len(value)-2]
	value = fmt.Sprintf("(%s)", value)

	return value
}
