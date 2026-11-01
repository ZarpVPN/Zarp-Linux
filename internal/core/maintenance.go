package core

import (
	"context"
	"errors"
)

func (e *Engine) Account(ctx context.Context) (string, error) {
	if b, ok := e.backend.(interface {
		ReadAccount(context.Context) (string, error)
	}); ok {
		return b.ReadAccount(ctx)
	}
	return "", errors.New("account_unavailable")
}
func (e *Engine) GeoStatus() any {
	if b, ok := e.backend.(interface{ GeographicStatus() any }); ok {
		return b.GeographicStatus()
	}
	return map[string]any{"geoip": map[string]any{"bundled": true}, "geosite": map[string]any{}}
}
func (e *Engine) DownloadGeo(ctx context.Context, kind, url string) error {
	b, ok := e.backend.(interface {
		DownloadGeo(context.Context, string, string, Config, func(string)) error
	})
	if !ok {
		return errors.New("demo_does_not_download")
	}
	work, finish, err := e.externalWork(ctx)
	if err != nil {
		return err
	}
	defer finish()
	return b.DownloadGeo(work, kind, url, e.Config(), e.emit)
}
func (e *Engine) CheckUpdates(ctx context.Context) (Object, error) {
	b, ok := e.backend.(interface {
		CheckUpdates(context.Context, Config, func(string)) (Object, error)
	})
	if !ok {
		return Object{"current": "demo", "available": ""}, nil
	}
	work, finish, err := e.externalWork(ctx)
	if err != nil {
		return nil, err
	}
	defer finish()
	return b.CheckUpdates(work, e.Config(), e.emit)
}
