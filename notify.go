package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// NotifyDiscord posts a detection summary to the configured Discord webhook.// File contents are never included.
func NotifyDiscord(cfg *Config, rep *Report) error { //nolint:gosec // webhook URL is owner-configured
	if cfg.DiscordWebhook == "" {
		return nil // notifications configured on, but no channel yet: log-only
	}
	var lines []string
	for i, d := range rep.Detections {
		if i >= 10 {
			lines = append(lines, fmt.Sprintf("… and %d more", len(rep.Detections)-10))
			break
		}
		lines = append(lines, fmt.Sprintf("`%s` — %s", d.Path, d.Signature))
	}
	host, _ := os.Hostname()
	payload := map[string]any{
		"embeds": []map[string]any{{
			"title":       fmt.Sprintf("WAMB: %d detection(s) on %s", len(rep.Detections), host),
			"description": strings.Join(lines, "\n"),
			"color":       0xD83C2E,
			"footer":      map[string]string{"text": "scan " + rep.ID + " (" + rep.Mode + ")"},
			"timestamp":   rep.EndedAt.UTC().Format(time.RFC3339),
		}},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post(cfg.DiscordWebhook, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("discord webhook returned %s", resp.Status)
	}
	return nil
}
