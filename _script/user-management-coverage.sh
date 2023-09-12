#!/bin/bash
go test -coverprofile=coverage.out ./user-management; go tool cover -func=coverage.out