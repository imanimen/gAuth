package main

import (
	"git.dyneemadev.com/micro-services/go-auth/invokers"
	"git.dyneemadev.com/micro-services/go-auth/providers"
	"go.uber.org/fx"
)

func main() {
	fx.New(
		fx.Provide(providers.NewConfig, providers.NewDatabase, providers.NewApi, providers.NewValidations),
		fx.Invoke(invokers.ApiServer),
	).Run()
}
