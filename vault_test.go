package vault

import (
	"context"
	"testing"

	"go.unistack.org/micro/v3/codec"
	"go.unistack.org/micro/v3/config"
)

func TestInit(t *testing.T) {
	c := NewConfig(
		config.Context(context.TODO()),
		config.Codec(codec.NewCodec()),
		config.BeforeInit(func(ctx context.Context, c config.Config) error {
			return c.Init(Token("tkn"), config.BeforeInit(nil))
		}),
	)

	if err := c.Init(); err != nil {
		t.Fatal(err)
	}
}
