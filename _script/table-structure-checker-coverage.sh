#!/bin/bash
go test -coverprofile=coverage.out ./table-structure-checker; go tool cover -func=coverage.out