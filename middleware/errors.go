package middleware

import "fmt"

// Middleware errors
var (
	ErrMissingAuthToken = fmt.Errorf("session token not found in cookies")
	ErrInvalidToken     = fmt.Errorf("invalid authorization token format")
	ErrExpiredSession   = fmt.Errorf("session has expired")
	ErrInvalidSession   = fmt.Errorf("invalid session")
)
