// @title gAuth API
// @version 1.0
// @description gAuth is a production authentication microservice: email OTP flows, Google OAuth social login and user profile management.
// @host localhost:8080
// @BasePath /
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization

package main

import (
	_ "github.com/imanimen/gAuth/docs"
	"github.com/imanimen/gAuth/invokers"
	"github.com/imanimen/gAuth/providers"
	"go.uber.org/fx"
)

func main() {
	fx.New(
		fx.Provide(
			providers.NewConfig,
			providers.NewDB,
			providers.NewDatabase,
			providers.NewValidations,
			providers.NewTokenManager,
			providers.NewOAuth,
			providers.NewApi,
			invokers.NewRouter,
		),
		fx.Invoke(invokers.ApiServer),
	).Run()
}
