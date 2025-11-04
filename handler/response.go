package handler

import (
	"encoding/json"
	"net/http"
)

// Response is the standard API response envelope
type Response struct {
	Success bool   `json:"success"`
	Data    any    `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

// ErrorResponse writes a JSON error response
func ErrorResponse(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(Response{
		Success: false,
		Message: message,
	})
}

// SuccessResponse writes a JSON success response
func SuccessResponse(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Data:    data,
	})
}

// HTTPError represents an HTTP error with status code
type HTTPError struct {
	Code    int
	Message string
}

// NewHTTPError creates a new HTTP error
func NewHTTPError(code int, message string) *HTTPError {
	return &HTTPError{
		Code:    code,
		Message: message,
	}
}

// BadRequest creates a 400 error
func BadRequest(message string) *HTTPError {
	return NewHTTPError(http.StatusBadRequest, message)
}

// Unauthorized creates a 401 error
func Unauthorized(message string) *HTTPError {
	return NewHTTPError(http.StatusUnauthorized, message)
}

// NotFound creates a 404 error
func NotFound(message string) *HTTPError {
	return NewHTTPError(http.StatusNotFound, message)
}

// Conflict creates a 409 error
func Conflict(message string) *HTTPError {
	return NewHTTPError(http.StatusConflict, message)
}

// InternalServerError creates a 500 error
func InternalServerError(message string) *HTTPError {
	return NewHTTPError(http.StatusInternalServerError, message)
}
