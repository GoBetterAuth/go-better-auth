package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/GoBetterAuth/go-better-auth/domain"
	"github.com/GoBetterAuth/go-better-auth/domain/user"
	"github.com/GoBetterAuth/go-better-auth/domain/verification"
	gobetterauthtests "github.com/GoBetterAuth/go-better-auth/tests"
	"github.com/GoBetterAuth/go-better-auth/usecase/auth"
	"github.com/GoBetterAuth/go-better-auth/vault"
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

	// Extract session cookie from sign in response
	cookies := signinW.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == handler.cookieManager.GetSessionCookieName() {
			sessionCookie = cookie
			break
		}
	}
	require.NotNil(t, sessionCookie, "Session cookie should be set")

	// Sign out with session cookie
	signoutHttpReq := httptest.NewRequest(http.MethodPost, "/auth/signout", nil)
	signoutHttpReq.AddCookie(sessionCookie)
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

	if resp.Message != "" {
		t.Errorf("Expected no error, got %s", resp.Message)
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

	if resp.Message != "bad request" {
		t.Errorf("Expected error 'bad request', got %s", resp.Message)
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
		Token:      vault.HashVerificationToken(verificationToken),
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
		Token:      vault.HashVerificationToken(verificationToken),
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
		Token:      vault.HashVerificationToken(verificationToken),
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

func TestSignInHandler_ReuseExistingSession(t *testing.T) {
	handler := setupTestHandler(t)

	// First, create a user and sign them in to get a session
	signUpReq := SignUpRequest{
		Email:    "reuse@example.com",
		Password: "ValidPassword123!",
		Name:     "Reuse Test User",
	}

	signUpBody, _ := json.Marshal(signUpReq)
	req := httptest.NewRequest(http.MethodPost, "/auth/sign-up/email", bytes.NewReader(signUpBody))
	w := httptest.NewRecorder()

	handler.SignUpHandler(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	bodyStr := w.Body.String()
	t.Logf("Response body: %s", bodyStr)

	// Need to re-create the reader since we read it above
	var envelope Response
	err := json.NewDecoder(strings.NewReader(bodyStr)).Decode(&envelope)
	require.NoError(t, err)
	require.True(t, envelope.Success)

	// Now decode the data part as SignUpResponse
	dataBytes, err := json.Marshal(envelope.Data)
	require.NoError(t, err)

	var signUpResponse SignUpResponse
	err = json.Unmarshal(dataBytes, &signUpResponse)
	require.NoError(t, err)

	originalToken := signUpResponse.Token

	// Extract the session cookie set by the signup
	cookies := w.Result().Cookies()
	expectedCookieName := handler.cookieManager.GetSessionCookieName()

	var sessionCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == expectedCookieName {
			sessionCookie = cookie
			break
		}
	}

	require.NotNil(t, sessionCookie, "Session cookie should be set")
	require.Equal(t, originalToken, sessionCookie.Value)

	// Now try to sign in with the same user, but include the existing session cookie
	signInReq := SignInRequest{
		Email:    "reuse@example.com",
		Password: "ValidPassword123!",
	}

	signInBody, _ := json.Marshal(signInReq)
	req2 := httptest.NewRequest(http.MethodPost, "/auth/sign-in/email", bytes.NewReader(signInBody))
	req2.AddCookie(sessionCookie) // Add the existing session cookie
	w2 := httptest.NewRecorder()

	handler.SignInHandler(w2, req2)
	require.Equal(t, http.StatusOK, w2.Code)

	signInBodyStr := w2.Body.String()

	var signInEnvelope Response
	err = json.NewDecoder(strings.NewReader(signInBodyStr)).Decode(&signInEnvelope)
	require.NoError(t, err)
	require.True(t, signInEnvelope.Success)

	signInDataBytes, err := json.Marshal(signInEnvelope.Data)
	require.NoError(t, err)

	var signInResponse SignInResponse
	err = json.Unmarshal(signInDataBytes, &signInResponse)
	require.NoError(t, err)

	// Verify that the same token is returned (session was reused)
	require.Equal(t, originalToken, signInResponse.Token)
	require.Equal(t, signUpResponse.User.ID, signInResponse.User.ID)
	require.Equal(t, signUpResponse.User.Email, signInResponse.User.Email)
}

func TestSignUpHandler_ReuseExistingSession(t *testing.T) {
	handler := setupTestHandler(t)

	// First, create a user and sign them in to get a session
	signUpReq := SignUpRequest{
		Email:    "reusesignup@example.com",
		Password: "ValidPassword123!",
		Name:     "Reuse Signup Test User",
	}

	signUpBody, _ := json.Marshal(signUpReq)
	req := httptest.NewRequest(http.MethodPost, "/auth/sign-up/email", bytes.NewReader(signUpBody))
	w := httptest.NewRecorder()

	handler.SignUpHandler(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	bodyStr := w.Body.String()

	var envelope Response
	err := json.NewDecoder(strings.NewReader(bodyStr)).Decode(&envelope)
	require.NoError(t, err)
	require.True(t, envelope.Success)

	dataBytes, err := json.Marshal(envelope.Data)
	require.NoError(t, err)

	var signUpResponse SignUpResponse
	err = json.Unmarshal(dataBytes, &signUpResponse)
	require.NoError(t, err)

	originalToken := signUpResponse.Token

	// Extract the session cookie set by the signup
	cookies := w.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == handler.cookieManager.GetSessionCookieName() {
			sessionCookie = cookie
			break
		}
	}
	require.NotNil(t, sessionCookie, "Session cookie should be set")

	// Try to sign up again with different details but include the existing session cookie
	// This should create a new user since signup doesn't check existing sessions
	signUp2Req := SignUpRequest{
		Email:    "different@example.com",
		Password: "DifferentPassword123!",
		Name:     "Different User",
	}

	signUp2Body, _ := json.Marshal(signUp2Req)
	req2 := httptest.NewRequest(http.MethodPost, "/auth/sign-up/email", bytes.NewReader(signUp2Body))
	req2.AddCookie(sessionCookie) // Add the existing session cookie
	w2 := httptest.NewRecorder()

	handler.SignUpHandler(w2, req2)
	require.Equal(t, http.StatusCreated, w2.Code) // Should be 201 (created) since it's a new user

	signUp2BodyStr := w2.Body.String()

	var signUp2Envelope Response
	err = json.NewDecoder(strings.NewReader(signUp2BodyStr)).Decode(&signUp2Envelope)
	require.NoError(t, err)
	require.True(t, signUp2Envelope.Success)

	signUp2DataBytes, err := json.Marshal(signUp2Envelope.Data)
	require.NoError(t, err)

	var signUp2Response SignUpResponse
	err = json.Unmarshal(signUp2DataBytes, &signUp2Response)
	require.NoError(t, err)

	// Verify that a new user is created with the different email
	require.NotEqual(t, originalToken, signUp2Response.Token)
	require.NotEqual(t, signUpResponse.User.ID, signUp2Response.User.ID)
	require.Equal(t, "different@example.com", signUp2Response.User.Email)
}
