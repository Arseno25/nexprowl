package report

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

func NotifyWebhook(ctx context.Context, endpoint string, payload any) error {
	if endpoint == "" {
		return nil
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	c, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(c, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("webhook status %d: %s", resp.StatusCode, msg)
	}
	return nil
}
