package didplc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/bluesky-social/indigo/atproto/crypto"
)

// the zero-value of this client is fully functional
type Client struct {
	DirectoryURL string
	UserAgent    string
	HTTPClient   http.Client
	RotationKey  *crypto.PrivateKey
}

var (
	ErrDIDNotFound      = errors.New("DID not found in PLC directory")
	DefaultDirectoryURL = "https://plc.directory"
)

// turn a non-200 HTTP response into a descriptive error, and log the body
func processErrorResponse(resp *http.Response, msg string) error {
	if resp.StatusCode == http.StatusNotFound {
		return ErrDIDNotFound
	}

	body := new(strings.Builder)
	_, err := io.Copy(body, resp.Body)
	if err != nil {
		slog.Info("failed reading PLC directory response body", "status_code", resp.StatusCode)
	} else {
		slog.Info("PLC directory request failed", "status_code", resp.StatusCode, "body", body.String())
	}

	return fmt.Errorf("%s, HTTP status: %d", msg, resp.StatusCode)
}

// common logic used for resolve, oplog, auditlog
func (c *Client) directoryGET(ctx context.Context, path string) (*http.Response, error) {
	plcURL := c.DirectoryURL
	if plcURL == "" {
		plcURL = DefaultDirectoryURL
	}

	req, err := http.NewRequestWithContext(ctx, "GET", plcURL+path, nil)
	if err != nil {
		return nil, err
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	} else {
		req.Header.Set("User-Agent", "go-did-method-plc")
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed did:plc directory request: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, processErrorResponse(resp, "failed did:plc directory request")
	}

	return resp, nil
}

func (c *Client) Resolve(ctx context.Context, did string) (*Doc, error) {
	if !strings.HasPrefix(did, "did:plc:") {
		return nil, fmt.Errorf("expected a did:plc, got: %s", did)
	}

	resp, err := c.directoryGET(ctx, "/"+did)
	if err != nil {
		return nil, err
	}

	var doc Doc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("failed parse of did:plc document JSON: %w", err)
	}
	return &doc, nil
}

func (c *Client) Submit(ctx context.Context, did string, op Operation) error {
	if !strings.HasPrefix(did, "did:plc:") {
		return fmt.Errorf("expected a did:plc, got: %s", did)
	}

	plcURL := c.DirectoryURL
	if plcURL == "" {
		plcURL = DefaultDirectoryURL
	}

	var body io.Reader
	b, err := json.Marshal(op)
	if err != nil {
		return err
	}
	body = bytes.NewReader(b)

	url := plcURL + "/" + did
	req, err := http.NewRequestWithContext(ctx, "POST", url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	} else {
		req.Header.Set("User-Agent", "go-did-method-plc")
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("did:plc operation submission failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return processErrorResponse(resp, "failed did:plc operation submission")
	}

	return nil
}

func (c *Client) OpLog(ctx context.Context, did string) ([]OpEnum, error) {
	if !strings.HasPrefix(did, "did:plc:") {
		return nil, fmt.Errorf("expected a did:plc, got: %s", did)
	}

	resp, err := c.directoryGET(ctx, "/"+did+"/log")
	if err != nil {
		return nil, err
	}

	var entries []OpEnum
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("failed parse of did:plc op log JSON: %w", err)
	}
	return entries, nil
}

func (c *Client) AuditLog(ctx context.Context, did string) ([]LogEntry, error) {
	if !strings.HasPrefix(did, "did:plc:") {
		return nil, fmt.Errorf("expected a did:plc, got: %s", did)
	}

	resp, err := c.directoryGET(ctx, "/"+did+"/log/audit")
	if err != nil {
		return nil, err
	}

	var entries []LogEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("failed parse of did:plc audit log JSON: %w", err)
	}
	return entries, nil
}
