package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// TestUser represents the user data structure for tests
type TestUser struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

// AuthTestSuite defines the test suite and holds the server instance
type AuthTestSuite struct {
	suite.Suite
	server *Server
	token  string // Store the token for authenticated requests
}

// SetupSuite is called once before running the tests in the suite
func (s *AuthTestSuite) SetupSuite() {
	gin.SetMode(gin.TestMode)
	s.server = NewServer()
	s.server.SetupRouter()
}

// performRequest is a helper function to perform HTTP requests
func (s *AuthTestSuite) performRequest(method, path string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(method, path, bytes.NewBuffer(body))

	// Set default Content-Type if not provided
	if _, exists := headers["Content-Type"]; !exists {
		req.Header.Set("Content-Type", "application/json")
	}

	// Set additional headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	s.server.router.ServeHTTP(w, req)
	return w
}

// TestRegister tests the user registration endpoint
func (s *AuthTestSuite) TestRegister() {
	user := TestUser{
		Username: "testuser",
		Password: "password123",
		Email:    "test@example.com",
	}

	jsonValue, _ := json.Marshal(user)
	w := s.performRequest("POST", "/register", jsonValue, nil)

	assert.Equal(s.T(), http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(s.T(), err)
	assert.Contains(s.T(), response, "token")
}

// TestLogin tests the login endpoint and stores the token
func (s *AuthTestSuite) TestLogin() {
	user := TestUser{
		Username: "testuser",
		Password: "password123",
		Email:    "test@example.com",
	}

	jsonValue, _ := json.Marshal(user)
	w := s.performRequest("POST", "/login", jsonValue, nil)

	assert.Equal(s.T(), http.StatusOK, w.Code)

	var response struct {
		Token string `json:"token"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(s.T(), err)

	s.token = response.Token
	assert.NotEmpty(s.T(), s.token)
}

// TestProfile tests the protected profile endpoint
func (s *AuthTestSuite) TestProfile() {
	headers := map[string]string{
		"Authorization": "Bearer " + s.token,
	}

	w := s.performRequest("GET", "/api/profile", nil, headers)
	assert.Equal(s.T(), http.StatusOK, w.Code)
}

// TestProfileUnauthorized tests accessing profile without token
func (s *AuthTestSuite) TestProfileUnauthorized() {
	w := s.performRequest("GET", "/api/profile", nil, nil)
	assert.Equal(s.T(), http.StatusUnauthorized, w.Code)
}

// TestAdminUsersUnauthorized tests the admin endpoint with non-admin token
func (s *AuthTestSuite) TestAdminUsersUnauthorized() {
	// 首先注册并登录一个普通用户
	user := TestUser{
		Username: "normaluser",
		Password: "password123",
		Email:    "",
	}

	// 登录获取 token
	jsonValue, _ := json.Marshal(user)
	w := s.performRequest("POST", "/login", jsonValue, nil)

	var response struct {
		Token string `json:"token"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(s.T(), err)

	normalUserToken := response.Token
	assert.NotEmpty(s.T(), normalUserToken)

	// 使用普通用户的 token 尝试访问管理员路由
	headers := map[string]string{
		"Authorization": "Bearer " + normalUserToken,
	}

	w = s.performRequest("GET", "/api/admin/users", nil, headers)
	assert.Equal(s.T(), http.StatusForbidden, w.Code, "Expected forbidden status for non-admin user")
}

// TestAdminUsersWithAdmin tests the admin endpoint with admin token
func (s *AuthTestSuite) TestAdminUsersWithAdmin() {
	// First register an admin user
	admin := TestUser{
		Username: "adminuser",
		Password: "admin123",
		Email:    "admin@example.com",
	}

	// Note: In a real application, you would have a separate mechanism to create admin users
	// This is just for testing purposes
	jsonValue, _ := json.Marshal(admin)
	w := s.performRequest("POST", "/register", jsonValue, nil)

	var response map[string]string
	json.Unmarshal(w.Body.Bytes(), &response)
	adminToken := response["token"]

	// Test admin endpoint with admin token
	headers := map[string]string{
		"Authorization": "Bearer " + adminToken,
	}

	w = s.performRequest("GET", "/api/admin/users", nil, headers)
	assert.Equal(s.T(), http.StatusOK, w.Code)
}

// TestInvalidToken tests using an invalid token
func (s *AuthTestSuite) TestInvalidToken() {
	headers := map[string]string{
		"Authorization": "Bearer invalid.token.here",
	}

	w := s.performRequest("GET", "/api/profile", nil, headers)
	assert.Equal(s.T(), http.StatusUnauthorized, w.Code)
}

// TestMain is the entry point for running the test suite
func TestAuthTestSuite(t *testing.T) {
	suite.Run(t, new(AuthTestSuite))
}
