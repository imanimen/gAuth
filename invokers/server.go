package invokers

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/imanimen/gAuth/middlewares"
	"github.com/imanimen/gAuth/providers"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"go.uber.org/fx"
)

// NewRouter builds the gin engine with middleware and the full route table.
func NewRouter(config providers.IConfig, api providers.IApi) *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())
	r.Use(versionMiddleware(config.Version()))

	if config.SwaggerEnabled() {
		r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	}

	InitRoutes(r, api)

	return r
}

// versionMiddleware stamps every request with the public API version so
// response helpers can build the standard envelope.
func versionMiddleware(version string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(providers.CtxVersionKey, version)
		c.Next()
	}
}

// InitRoutes registers every endpoint, including the swagger UI when the
// host application already mounted it.
func InitRoutes(engine *gin.Engine, api providers.IApi) {
	// auth (public)
	engine.POST("/api/auth/send", api.SendOtp)
	engine.POST("/api/auth/resend", api.ResendOtp)
	engine.POST("/api/auth/verify", api.VerifyOtp)

	// social auth (public)
	engine.GET("/api/oauth/redirect", api.OauthRedirect)
	engine.GET("/api/oauth/callback", api.OauthCallBack)

	// authorized routes
	authorized := engine.Group("/auth")
	authorized.Use(middlewares.AuthMiddleware(api.GetUserByID, api.TokenManager()))
	{
		// user routes
		authorized.GET("/user/:id", api.GetUser)
		authorized.GET("/user/check", api.Check)
		authorized.GET("/user/platform", api.GetUserTokenPlatform)
		authorized.GET("/user/users", api.UsersPagination)
		authorized.GET("/user/all-users", api.AllUsers)
		authorized.POST("/user/select", api.SelectedUsers)
		authorized.POST("/user/update-username", api.UpdateUserName)
		authorized.POST("/user/validate-username", api.ValidateUserName)
		authorized.POST("/user/update", api.UpdateProfile)
		authorized.POST("/user/remove-profile", api.RemoveProfile)
		authorized.POST("/user/add-category", api.AddCategory)
		authorized.POST("/user/delete-category", api.DeleteCategory)
	}
}

// ApiServer serves the router over HTTP with a graceful shutdown hook.
func ApiServer(lc fx.Lifecycle, engine *gin.Engine, config providers.IConfig) {
	server := &http.Server{
		Addr:              ":" + config.Port(),
		Handler:           engine,
		ReadHeaderTimeout: 10 * time.Second,
	}

	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			go func() {
				if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					panic(err)
				}
			}()
			return nil
		},
		OnStop: func(ctx context.Context) error {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return server.Shutdown(shutdownCtx)
		},
	})
}
