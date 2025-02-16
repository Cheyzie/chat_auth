package handlers

import (
	"net/http"

	"github.com/Cheyzie/chat_auth/internal/model"
	"github.com/Cheyzie/chat_auth/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type Handler struct {
	authService *service.AuthorizationService
}

func NewHandler(authService *service.AuthorizationService) *Handler {
	return &Handler{authService: authService}
}

func (h *Handler) InitRoutes() *gin.Engine {
	router := gin.Default()

	// router.Use(
	// 	cors.New(cors.Config{
	// 		AllowAllOrigins:        true,
	// 		AllowMethods:           []string{"GET", "POST", "PUT", "DELETE"},
	// 		AllowHeaders:           []string{"ORIGIN", "Authorization", "Content-Type"},
	// 		AllowCredentials:       true,
	// 		AllowBrowserExtensions: true,
	// 		MaxAge:                 300 * time.Second,
	// 	}),
	// )
	router.GET("/", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"message": "hello world",
		})
	})
	api := router.Group("/api/v1")
	{
		api.POST("/signin", h.signIn)
		api.POST("/signup", h.signUp)
		api.POST("/refresh", h.refreshToken)
		securedRouter := api.Group("/")
		securedRouter.Use(h.userIdentity)
		securedRouter.GET("/me", h.getMe)
		securedRouter.GET("/me/sessions", h.userSessions)
		securedRouter.DELETE("/sessions/:id", h.dropSession)
		securedRouter.DELETE("/signout", h.signOut)
	}

	return router
}

func newErrorResponse(ctx *gin.Context, statusCode int, message string, err error) {
	if err != nil {
		logrus.Error(err.Error())
	}
	ctx.AbortWithStatusJSON(statusCode, model.Error{Message: message})
}
