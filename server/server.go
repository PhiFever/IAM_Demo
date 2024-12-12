package server

import (
	"IAM_Demo/handlers"
	"IAM_Demo/middleware"
	"IAM_Demo/models"
	"IAM_Demo/services"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"net/http"
)

type Server struct {
	router      *gin.Engine
	authService *services.AuthService
	permService *services.PermissionService
}

func NewServer() *Server {
	server := &Server{
		router:      gin.Default(),
		authService: services.NewAuthService(),
		permService: services.NewPermissionService(),
	}

	// 初始化默认权限
	server.setupDefaultPermissions()

	return server
}

func (s *Server) setupDefaultPermissions() {
	s.permService.AddRole(models.Role{
		Name: "defaultUser",
		Type: models.RoleUser,
		Permissions: []models.Permission{
			{Resource: models.ResourceProduct, Action: models.ActionRead},
		},
	})
	s.permService.AddRole(models.Role{
		Name: "defaultAdmin",
		Type: models.RoleAdmin,
		Permissions: []models.Permission{
			{Resource: models.ResourceProduct, Action: models.ActionWrite},
			{Resource: models.ResourceUser, Action: models.ActionWrite},
		},
	})
}

func (s *Server) setupPublicRoutes() {
	s.router.POST("/register", func(c *gin.Context) {
		handlers.RegisterHandler(c, s.authService)
	})

	s.router.POST("/login", func(c *gin.Context) {
		handlers.LoginHandler(c, s.authService)
	})
}

func (s *Server) setupAdminRoutes(adminGroup *gin.RouterGroup) {
	admin := adminGroup.Group("/admin")
	{
		// 将管理员检查移到具体的处理函数中
		admin.GET("/users", func(c *gin.Context) {
			// 首先获取用户信息
			userClaims, exists := c.Get("user")
			if !exists {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found in context"})
				return
			}

			claims := userClaims.(jwt.MapClaims)
			if claims["role"] != "admin" {
				c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"message": "Admin only resource",
				"users": []gin.H{
					{"username": "user1", "role": "user"},
					{"username": "user2", "role": "user"},
					{"username": "admin1", "role": "admin"},
				},
			})
		})
	}
}

func (s *Server) setupProtectedRoutes() {
	protected := s.router.Group("/api")
	protected.Use(middleware.GinAuthMiddleware(s.authService))
	{
		protected.GET("/profile", handlers.ProtectedHandler)

		// 设置管理员路由
		s.setupAdminRoutes(protected)
	}
}

func (s *Server) SetupRouter() {
	// 设置公开路由
	s.setupPublicRoutes()

	// 设置受保护的路由
	s.setupProtectedRoutes()
}

func (s *Server) Start(addr string) error {
	return s.router.Run(addr)
}
