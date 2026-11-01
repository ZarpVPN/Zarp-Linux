package linux

import (
	"context"
	"errors"
	"strings"
	"time"
)

func (b *Backend) ReadAccount(ctx context.Context) (string, error) {
	cli, err := SystemPath("warp-cli")
	if err != nil {
		return "", errors.New("warp_not_installed")
	}
	limit, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	out, err := Run(limit, cli, nil, "registration", "show")
	if err != nil {
		if confirmedMissing(out) {
			return "unknown", nil
		}
		return "", errors.New("warp_account_status_unavailable")
	}
	if match := accountPattern.FindStringSubmatch(out); len(match) == 2 {
		return strings.ToLower(match[1]), nil
	}
	return "unknown", nil
}
