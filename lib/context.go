package lib

import (
	"context"
	"time"
)

func InitializeContex() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}
