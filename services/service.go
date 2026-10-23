package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const defaultHTTPTimeout = 15 * time.Second

// Call makes an HTTP request to the specified URL using the provided method
// and payload. It returns the decoded JSON response as a
// map[string]interface{} and any error that occurred during the request.
// Non 2xx status codes are treated as errors.
func Call(url string, method string, payload []byte) (map[string]interface{}, error) {
	if url == "" {
		return nil, errors.New("empty request url")
	}

	client := &http.Client{Timeout: defaultHTTPTimeout}
	var body io.Reader
	if payload != nil {
		body = bytes.NewBuffer(payload)
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}

	var result map[string]interface{}
	if len(data) == 0 {
		return result, nil
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return result, nil
}

// DispatchOTPNotification sends an OTP email request to the notification
// service in the background. Failures are logged and do not affect the
// caller. It is a no-op when notifyURL is empty.
func DispatchOTPNotification(notifyURL, code, email string) {
	if notifyURL == "" {
		return
	}
	payload := []byte(fmt.Sprintf(`{
		"type": ["email"],
		"payload": %q,
		"destination": %q,
		"mail_type": "otp"
	}`, code, email))

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), defaultHTTPTimeout)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, notifyURL, bytes.NewBuffer(payload))
		if err != nil {
			fmt.Println("otp notification: building request failed:", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := (&http.Client{Timeout: defaultHTTPTimeout}).Do(req)
		if err != nil {
			fmt.Println("otp notification: dispatch failed:", err)
			return
		}
		defer func() {
			_ = resp.Body.Close()
		}()
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			fmt.Printf("otp notification: unexpected status %d from %s\n", resp.StatusCode, notifyURL)
		}
	}()
}

// GetEnv returns the value of the given environment variable or the fallback
// when it is unset. It is a small helper for optional service locations that
// are not part of the typed configuration.
func GetEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
