#!/bin/bash
go test -coverprofile=coverage.out ./user-management-repository; go tool cover -func=coverage.out