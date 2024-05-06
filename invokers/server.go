package invokers

import (
	"context"
	"errors"

	"git.dyneemadev.com/micro-services/go-auth/middlewares"
	"git.dyneemadev.com/micro-services/go-auth/providers"
	"github.com/gin-gonic/gin"
	"go.uber.org/fx"
)

func ApiServer(lc fx.Lifecycle, api providers.IApi) *gin.Engine {
	r := gin.Default()
	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			InitRoutes(r, api)
			go r.Run()
			return nil
		},
		OnStop: func(ctx context.Context) error {
			// TODO : gracefull
			return errors.New("server going down")
		},
	})
	return r
}

func InitRoutes(engine *gin.Engine, api providers.IApi) {

	engine.GET("/api/user/:id", api.GetUser)
	engine.POST("/api/auth/send", api.SendOtp)
	engine.POST("/api/auth/resend", api.ResendOtp)
	engine.POST("/api/auth/verify", api.VerifyOtp)
	// social auth api
	engine.GET("/api/oauth/redirect", api.OauthRedirect)
	engine.GET("/api/oauth/callback", api.OauthCallBack)
	// authorized routes
	authorized := engine.Group("/auth")
	engine.Use(gin.Logger())

	// Recovery middleware recovers from any panics and writes a 500 if there was one.
	engine.Use(gin.Recovery())

	authorized.Use(middlewares.AuthMiddleware(api.GetUserById))
	{
		// auth routes
		authorized.GET("user/:id", api.GetUser)
		authorized.GET("user/check", api.Check)
		authorized.GET("user/platform", api.GetUserTokenPlatform)
		authorized.GET("user/users", api.UsersPagination)
		authorized.GET("user/all-users", api.AllUsers)
		authorized.GET("user/select", api.SelectedUsers)
		authorized.POST("user/update-username", api.UpdateUserName)
		authorized.POST("user/validate-username", api.ValidateUserName)
		authorized.POST("user/update", api.UpdateProfile)
		authorized.POST("user/remove-profile", api.RemoveProfile)
		authorized.POST("user/add-category", api.AddCategory)
		authorized.POST("user/delete-category", api.DeleteCategory)
	}

}
