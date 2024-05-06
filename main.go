package main

import (
	"github.com/imanimen/gAuth/invokers"
	"github.com/imanimen/gAuth/providers"
	"go.uber.org/fx"
)

func main() {
	fx.New(
		fx.Provide(providers.NewConfig, providers.NewDatabase, providers.NewApi, providers.NewValidations),
		fx.Invoke(invokers.ApiServer),
	).Run()
}
