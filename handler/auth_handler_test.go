package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GoBetterAuth/go-better-auth/domain"
	"github.com/GoBetterAuth/go-better-auth/domain/user"
	"github.com/GoBetterAuth/go-better-auth/domain/verification"
	"github.com/GoBetterAuth/go-better-auth/internal/crypto"
	gobetterauthtests "github.com/GoBetterAuth/go-better-auth/tests"
	"github.com/GoBetterAuth/go-better-auth/usecase/auth"
)

func setupTestHandler(t *testing.T) *AuthHandler {
	t.Helper()

	config := gobetterauthtests.CreateTestConfig()

	testRepos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	t.Cleanup(cleanup)

	authService := auth.NewService(
		config,
		testRepos.UserRepo,
		testRepos.SessionRepo,
		testRepos.AccountRepo,
		testRepos.VerificationRepo,
	)
	cookieManager := NewCookieManager(config)

	return &AuthHandler{
		service:       authService,
		cookieManager: cookieManager,
	}
}

func TestSignUpHandler_Valid(t *testing.T) {
	handler := setupTestHandler(t)

	req := SignUpRequest{
		Email:    "test@example.com",
		Password: "ValidPassword123!",
		Name:     "Test User",
	}

	body, _ := json.Marshal(req)
	httpReq := httptest.NewRequest(http.MethodPost, "/auth/signup", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.SignUpHandler(w, httpReq)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d", http.StatusCreated, w.Code)
	}

	var resp Response
	json.NewDecoder(w.Body).Decode(&resp)

	if !resp.Success {
		t.Error("Expected success response")
	}

	data := resp.Data.(map[string]interface{})
	if data["token"] == nil {
		t.Error("Expected token in response")
	}

	user := data["user"].(map[string]interface{})
	if user["email"] != req.Email {
		t.Errorf("Expected email %s, got %v", req.Email, user["email"])
	}
}

func TestSignUpHandler_InvalidMethod(t *testing.T) {
	handler := setupTestHandler(t)

	httpReq := httptest.NewRequest(http.MethodGet, "/auth/signup", nil)
	w := httptest.NewRecorder()

	handler.SignUpHandler(w, httpReq)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestSignUpHandler_InvalidBody(t *testing.T) {
	handler := setupTestHandler(t)

	httpReq := httptest.NewRequest(http.MethodPost, "/auth/signup", bytes.NewReader([]byte("invalid json")))
	w := httptest.NewRecorder()

	handler.SignUpHandler(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestSignUpHandler_DuplicateEmail(t *testing.T) {
	handler := setupTestHandler(t)

	// Create first user
	req1 := SignUpRequest{
		Email:    "test@example.com",
		Password: "ValidPassword123!",
		Name:     "Test User",
	}
	body1, _ := json.Marshal(req1)
	httpReq1 := httptest.NewRequest(http.MethodPost, "/auth/signup", bytes.NewReader(body1))
	w1 := httptest.NewRecorder()
	handler.SignUpHandler(w1, httpReq1)

	// Try to create second user with same email
	req2 := SignUpRequest{
		Email:    "test@example.com",
		Password: "DifferentPassword456!",
		Name:     "Another User",
	}
	body2, _ := json.Marshal(req2)
	httpReq2 := httptest.NewRequest(http.MethodPost, "/auth/signup", bytes.NewReader(body2))
	w2 := httptest.NewRecorder()
	handler.SignUpHandler(w2, httpReq2)

	if w2.Code != http.StatusConflict {
		t.Errorf("Expected status %d, got %d", http.StatusConflict, w2.Code)
	}
}

func TestSignInHandler_Valid(t *testing.T) {
	handler := setupTestHandler(t)

	// Sign up first
	signupReq := SignUpRequest{
		Email:    "test@example.com",
		Password: "ValidPassword123!",
		Name:     "Test User",
	}
	body, _ := json.Marshal(signupReq)
	httpReq := httptest.NewRequest(http.MethodPost, "/auth/signup", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.SignUpHandler(w, httpReq)

	// Now sign in
	signinReq := SignInRequest{
		Email:    "test@example.com",
		Password: "ValidPassword123!",
	}
	signinBody, _ := json.Marshal(signinReq)
	signinHttpReq := httptest.NewRequest(http.MethodPost, "/auth/signin", bytes.NewReader(signinBody))
	signinW := httptest.NewRecorder()

	handler.SignInHandler(signinW, signinHttpReq)

	if signinW.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, signinW.Code)
	}

	var resp Response
	json.NewDecoder(signinW.Body).Decode(&resp)

	if !resp.Success {
		t.Error("Expected success response")
	}
}

func TestSignInHandler_InvalidPassword(t *testing.T) {
	handler := setupTestHandler(t)

	// Sign up first
	signupReq := SignUpRequest{
		Email:    "test@example.com",
		Password: "ValidPassword123!",
		Name:     "Test User",
	}
	body, _ := json.Marshal(signupReq)
	httpReq := httptest.NewRequest(http.MethodPost, "/auth/signup", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.SignUpHandler(w, httpReq)

	// Try to sign in with wrong password
	signinReq := SignInRequest{
		Email:    "test@example.com",
		Password: "WrongPassword456!",
	}
	signinBody, _ := json.Marshal(signinReq)
	signinHttpReq := httptest.NewRequest(http.MethodPost, "/auth/signin", bytes.NewReader(signinBody))
	signinW := httptest.NewRecorder()

	handler.SignInHandler(signinW, signinHttpReq)

	if signinW.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, signinW.Code)
	}
}

func TestSignOutHandler_Valid(t *testing.T) {
	handler := setupTestHandler(t)

	// Sign up and sign in
	signupReq := SignUpRequest{
		Email:    "test@example.com",
		Password: "ValidPassword123!",
		Name:     "Test User",
	}
	body, _ := json.Marshal(signupReq)
	httpReq := httptest.NewRequest(http.MethodPost, "/auth/signup", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.SignUpHandler(w, httpReq)

	signinReq := SignInRequest{
		Email:    "test@example.com",
		Password: "ValidPassword123!",
	}
	signinBody, _ := json.Marshal(signinReq)
	signinHttpReq := httptest.NewRequest(http.MethodPost, "/auth/signin", bytes.NewReader(signinBody))
	signinW := httptest.NewRecorder()

	handler.SignInHandler(signinW, signinHttpReq)

	var signinResp Response
	json.NewDecoder(signinW.Body).Decode(&signinResp)
	signinData := signinResp.Data.(map[string]interface{})
	token := signinData["token"].(string)

	// Sign out
	signoutReq := SignOutRequest{
		Token: token,
	}
	signoutBody, _ := json.Marshal(signoutReq)
	signoutHttpReq := httptest.NewRequest(http.MethodPost, "/auth/signout", bytes.NewReader(signoutBody))
	signoutW := httptest.NewRecorder()

	handler.SignOutHandler(signoutW, signoutHttpReq)

	if signoutW.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, signoutW.Code)
	}
}

func TestValidateSessionHandler_Valid(t *testing.T) {
	handler := setupTestHandler(t)

	// Sign up and sign in to get token
	signupReq := SignUpRequest{
		Email:    "test@example.com",
		Password: "ValidPassword123!",
		Name:     "Test User",
	}
	body, _ := json.Marshal(signupReq)
	httpReq := httptest.NewRequest(http.MethodPost, "/auth/signup", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.SignUpHandler(w, httpReq)

	signinReq := SignInRequest{
		Email:    "test@example.com",
		Password: "ValidPassword123!",
	}
	signinBody, _ := json.Marshal(signinReq)
	signinHttpReq := httptest.NewRequest(http.MethodPost, "/auth/signin", bytes.NewReader(signinBody))
	signinW := httptest.NewRecorder()

	handler.SignInHandler(signinW, signinHttpReq)

	var signinResp Response
	json.NewDecoder(signinW.Body).Decode(&signinResp)
	signinData := signinResp.Data.(map[string]interface{})
	token := signinData["token"].(string)

	// Validate session
	validateHttpReq := httptest.NewRequest(http.MethodGet, "/auth/validate", nil)
	validateHttpReq.Header.Set("Authorization", "Bearer "+token)
	validateW := httptest.NewRecorder()

	handler.ValidateSessionHandler(validateW, validateHttpReq)

	if validateW.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, validateW.Code)
	}

	var validateResp Response
	json.NewDecoder(validateW.Body).Decode(&validateResp)

	if !validateResp.Success {
		t.Error("Expected success response")
	}
}

func TestValidateSessionHandler_InvalidToken(t *testing.T) {
	handler := setupTestHandler(t)

	validateHttpReq := httptest.NewRequest(http.MethodGet, "/auth/validate", nil)
	validateHttpReq.Header.Set("Authorization", "Bearer invalid-token")
	validateW := httptest.NewRecorder()

	handler.ValidateSessionHandler(validateW, validateHttpReq)

	if validateW.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, validateW.Code)
	}
}

func TestResponseEnvelope_Success(t *testing.T) {
	w := httptest.NewRecorder()
	SuccessResponse(w, http.StatusOK, map[string]string{"key": "value"})

	var resp Response
	json.NewDecoder(w.Body).Decode(&resp)

	if !resp.Success {
		t.Error("Expected success = true")
	}

	if resp.Error != "" {
		t.Errorf("Expected no error, got %s", resp.Error)
	}
}

func TestResponseEnvelope_Error(t *testing.T) {
	w := httptest.NewRecorder()
	ErrorResponse(w, http.StatusBadRequest, "bad request")

	var resp Response
	json.NewDecoder(w.Body).Decode(&resp)

	if resp.Success {
		t.Error("Expected success = false")
	}

	if resp.Error != "bad request" {
		t.Errorf("Expected error 'bad request', got %s", resp.Error)
	}
}

// Email Verification Tests

func TestVerifyEmailGetHandler_ValidToken(t *testing.T) {
	// Setup repositories
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	// Create a user
	testUser := &user.User{
		ID:            "test-user-id",
		Email:         "verify@example.com",
		EmailVerified: false,
		Name:          "Test User",
	}
	err := repos.UserRepo.Create(testUser)
	require.NoError(t, err)

	// Create verification token
	verificationToken := "valid-token-12345"
	v := &verification.Verification{
		Identifier: testUser.Email,
		Token:      crypto.HashVerificationToken(verificationToken),
		Type:       verification.TypeEmailVerification,
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		CreatedAt:  time.Now(),
	}
	err = repos.VerificationRepo.Create(v)
	require.NoError(t, err)

	// Make request
	httpReq := httptest.NewRequest(http.MethodGet, "/auth/verify-email?token="+verificationToken, nil)
	w := httptest.NewRecorder()

	// Create service with configuration for this test
	config := &domain.Config{}
	config.ApplyDefaults()
	config.BaseURL = "https://example.com"

	service := auth.NewService(
		config,
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)
	cookieManager := NewCookieManager(config)
	handler := &AuthHandler{
		service:       service,
		cookieManager: cookieManager,
	}

	handler.VerifyEmailHandler(w, httpReq)

	// Verify redirect
	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Verify user email is now verified
	verifiedUser, _ := repos.UserRepo.FindByID(testUser.ID)
	if !verifiedUser.EmailVerified {
		t.Error("Expected user email to be verified")
	}

	// Verify token is deleted
	_, err = repos.VerificationRepo.FindByHashedToken(verificationToken)
	if err == nil {
		t.Error("Expected verification token to be deleted")
	}
}

func TestVerifyEmailGetHandler_MissingToken(t *testing.T) {
	handler := setupTestHandler(t)

	httpReq := httptest.NewRequest(http.MethodGet, "/auth/verify-email", nil)
	w := httptest.NewRecorder()

	handler.VerifyEmailHandler(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestVerifyEmailGetHandler_InvalidToken(t *testing.T) {
	handler := setupTestHandler(t)

	httpReq := httptest.NewRequest(http.MethodGet, "/auth/verify-email?token=invalid-token", nil)
	w := httptest.NewRecorder()

	handler.VerifyEmailHandler(w, httpReq)

	// Invalid token should return 401 Unauthorized
	if w.Code != http.StatusUnauthorized && w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 401 or 500, got %d", w.Code)
	}
}

func TestVerifyEmailGetHandler_ExpiredToken(t *testing.T) {
	// Setup repositories
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	// Create a user
	testUser := &user.User{
		ID:            "test-user-id",
		Email:         "verify@example.com",
		EmailVerified: false,
		Name:          "Test User",
	}
	err := repos.UserRepo.Create(testUser)
	require.NoError(t, err)

	// Create expired verification token
	verificationToken := "expired-token-12345"
	v := &verification.Verification{
		Identifier: testUser.Email,
		Token:      crypto.HashVerificationToken(verificationToken),
		Type:       verification.TypeEmailVerification,
		ExpiresAt:  time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
		CreatedAt:  time.Now().Add(-2 * time.Hour),
	}
	err = repos.VerificationRepo.Create(v)
	require.NoError(t, err)

	httpReq := httptest.NewRequest(http.MethodGet, "/auth/verify-email?token="+verificationToken, nil)
	w := httptest.NewRecorder()

	config := &domain.Config{}
	config.ApplyDefaults()

	service := auth.NewService(
		config,
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)
	cookieManager := NewCookieManager(config)
	handler := &AuthHandler{
		service:       service,
		cookieManager: cookieManager,
	}

	handler.VerifyEmailHandler(w, httpReq)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestVerifyEmailGetHandler_InvalidMethod(t *testing.T) {
	handler := setupTestHandler(t)

	// Test with invalid method (PUT)
	httpReq := httptest.NewRequest(http.MethodPut, "/auth/verify-email", nil)
	w := httptest.NewRecorder()

	handler.VerifyEmailHandler(w, httpReq)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestVerifyEmailGetHandler_CustomRedirectURL(t *testing.T) {
	// Setup repositories
	repos, cleanup := gobetterauthtests.SetupTestRepositories(t)
	defer cleanup()

	// Create a user
	testUser := &user.User{
		ID:            "test-user-id",
		Email:         "verify@example.com",
		EmailVerified: false,
		Name:          "Test User",
	}
	err := repos.UserRepo.Create(testUser)
	require.NoError(t, err)

	// Create verification token
	verificationToken := "valid-token-12345"
	v := &verification.Verification{
		Identifier: testUser.Email,
		Token:      crypto.HashVerificationToken(verificationToken),
		Type:       verification.TypeEmailVerification,
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		CreatedAt:  time.Now(),
	}
	err = repos.VerificationRepo.Create(v)
	require.NoError(t, err)

	httpReq := httptest.NewRequest(http.MethodGet, "/auth/verify-email?token="+verificationToken+"&callbackURL=https://example.com/login?verified=true", nil)
	w := httptest.NewRecorder()

	config := &domain.Config{}
	config.ApplyDefaults()
	config.BaseURL = "https://example.com"
	config.EmailVerification = &domain.EmailVerificationConfig{
		ExpiresIn:             24 * time.Hour,
		SendVerificationEmail: nil,
	}
	service := auth.NewService(
		config,
		repos.UserRepo,
		repos.SessionRepo,
		repos.AccountRepo,
		repos.VerificationRepo,
	)
	cookieManager := NewCookieManager(config)
	handler := &AuthHandler{
		service:       service,
		cookieManager: cookieManager,
	}

	handler.VerifyEmailHandler(w, httpReq)

	if w.Code != http.StatusSeeOther {
		t.Errorf("Expected status %d, got %d", http.StatusSeeOther, w.Code)
	}

	location := w.Header().Get("Location")
	parsedLocation, err := url.Parse(location)
	if err != nil {
		t.Fatalf("Expected redirect URL to be valid but got error: %v", err)
	}

	if parsedLocation.Scheme != "https" || parsedLocation.Host != "example.com" || parsedLocation.Path != "/login" {
		t.Fatalf("Unexpected redirect target: %s", location)
	}

	query := parsedLocation.Query()
	if query.Get("verified") != "true" {
		t.Fatalf("Expected verified query param to be preserved, got %s", query.Get("verified"))
	}
	if query.Get("token") != verificationToken {
		t.Fatalf("Expected token query param to be appended, got %s", query.Get("token"))
	}
	if query.Get("type") != string(verification.TypeEmailVerification) {
		t.Fatalf("Expected type query param to be appended, got %s", query.Get("type"))
	}
}
