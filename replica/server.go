package replica

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/carlmjohnson/versioninfo"
	"github.com/did-method-plc/go-didplc/didplc"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

const indexBanner string = `
       .__                                         .__  .__
______ |  |   ____           _______   ____ ______ |  | |__| ____ _____
\____ \|  | _/ ___\   ______ \_  __ \_/ __ \\____ \|  | |  |/ ___\\__  \
|  |_> >  |_\  \___  /_____/  |  | \/\  ___/|  |_> >  |_|  \  \___ / __ \_
|   __/|____/\___  >          |__|    \___  >   __/|____/__|\___  >____  /
|__|             \/                       \/|__|                \/     \/


This is a did:plc read-replica service.

  Source: https://github.com/did-method-plc/go-didplc/tree/main/cmd/replica
 Version: %s
`

// DIDDataResponse is the response for GET /{did}/data
type DIDDataResponse struct {
	DID                 string                      `json:"did"`
	VerificationMethods map[string]string           `json:"verificationMethods"`
	RotationKeys        []string                    `json:"rotationKeys"`
	AlsoKnownAs         []string                    `json:"alsoKnownAs"`
	Services            map[string]didplc.OpService `json:"services"`
}

// Server holds the HTTP server and its dependencies
type Server struct {
	store  *GormOpStore
	addr   string
	logger *slog.Logger
}

// NewServer creates a new HTTP server
func NewServer(store *GormOpStore, addr string, logger *slog.Logger) *Server {
	return &Server{
		store:  store,
		addr:   addr,
		logger: logger.With("component", "server"),
	}
}

// Run starts the HTTP server (blocking)
func (s *Server) Run() error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /_health", s.handleHealth)
	mux.HandleFunc("GET /{did}/log/audit", s.handleDIDLogAudit)
	mux.HandleFunc("GET /{did}/log/last", s.handleDIDLogLast)
	mux.HandleFunc("GET /{did}/log", s.handleDIDLog)
	mux.HandleFunc("GET /{did}/data", s.handleDIDData)
	mux.HandleFunc("GET /{did}", s.handleDIDDoc)
	mux.HandleFunc("GET /{$}", s.handleIndex)

	handler := otelhttp.NewHandler(mux, "")

	s.logger.Info("http server listening", "addr", s.addr)
	return http.ListenAndServe(s.addr, handler)
}

// handleIndex serves the index page
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, indexBanner, versioninfo.Short())
}

// handleHealth handles GET /_health - returns version information
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, "application/json", map[string]string{
		"version": versioninfo.Short(),
	})
}

// formatTimestamp formats a time.Time as a JS-style ISO 8601 timestamp.
func formatTimestamp(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

// writeJSON marshals v to JSON and writes it to w with the given content type.
// If marshaling fails, it sends a 500 error. If writing fails, it logs the error.
// Optional extra headers are set before writing the response.
func (s *Server) writeJSON(w http.ResponseWriter, contentType string, v any, extraHeaders ...http.Header) {
	data, err := json.Marshal(v)
	if err != nil {
		s.writeJSONError(w, fmt.Sprintf("error encoding response: %v", err), http.StatusInternalServerError)
		return
	}
	for _, h := range extraHeaders {
		for k, vs := range h {
			for _, val := range vs {
				w.Header().Set(k, val)
			}
		}
	}
	w.Header().Set("Content-Type", contentType)
	if _, err := w.Write(data); err != nil {
		s.logger.Error("failed to write response", "err", err)
	}
}

// writeJSONError writes a JSON error response
func (s *Server) writeJSONError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]string{"message": message}); err != nil {
		s.logger.Error("failed to encode error response", "err", err)
	}
}

// handleDIDDoc handles GET /{did} - returns the DID document
func (s *Server) handleDIDDoc(w http.ResponseWriter, r *http.Request) {
	did := r.PathValue("did")
	ctx := r.Context()

	head, err := s.store.GetLatest(ctx, did)
	if err != nil {
		s.writeJSONError(w, fmt.Sprintf("error fetching from store: %v", err), http.StatusInternalServerError)
		return
	}
	if head == nil {
		s.writeJSONError(w, fmt.Sprintf("DID not registered: %s", did), http.StatusNotFound)
		return
	}

	// Generate DID document
	doc, err := head.Op.Doc(did)
	if err != nil {
		s.writeJSONError(w, fmt.Sprintf("error generating DID document: %v", err), http.StatusInternalServerError)
		return
	}

	s.writeJSON(w, "application/did+json", doc, http.Header{
		"Last-Modified": {formatTimestamp(head.CreatedAt)},
	})
}

// handleDIDData handles GET /{did}/data - returns the latest operation data
func (s *Server) handleDIDData(w http.ResponseWriter, r *http.Request) {
	did := r.PathValue("did")
	ctx := r.Context()

	head, err := s.store.GetLatest(ctx, did)
	if err != nil {
		s.writeJSONError(w, fmt.Sprintf("error fetching from store: %v", err), http.StatusInternalServerError)
		return
	}
	if head == nil {
		s.writeJSONError(w, fmt.Sprintf("DID not registered: %s", did), http.StatusNotFound)
		return
	}

	// Build response based on operation type
	var resp DIDDataResponse
	resp.DID = did

	switch v := head.Op.(type) {
	case *didplc.RegularOp:
		resp.RotationKeys = v.RotationKeys
		resp.VerificationMethods = v.VerificationMethods
		resp.AlsoKnownAs = v.AlsoKnownAs
		resp.Services = v.Services
	case *didplc.LegacyOp:
		// Convert legacy op to regular op format
		regular := v.RegularOp()
		resp.RotationKeys = regular.RotationKeys
		resp.VerificationMethods = regular.VerificationMethods
		resp.AlsoKnownAs = regular.AlsoKnownAs
		resp.Services = regular.Services
	case *didplc.TombstoneOp:
		s.writeJSONError(w, fmt.Sprintf("DID not available: %s", did), http.StatusNotFound)
		return
	default:
		s.writeJSONError(w, "unknown operation type", http.StatusInternalServerError)
		return
	}

	s.writeJSON(w, "application/json", resp)
}

// handleDIDLogAudit handles GET /{did}/log/audit - returns the full audit log with metadata
func (s *Server) handleDIDLogAudit(w http.ResponseWriter, r *http.Request) {
	did := r.PathValue("did")
	ctx := r.Context()

	allEntries, err := s.store.GetAllEntries(ctx, did)
	if err != nil {
		s.writeJSONError(w, fmt.Sprintf("error fetching audit log: %v", err), http.StatusInternalServerError)
		return
	}

	if len(allEntries) == 0 {
		s.writeJSONError(w, fmt.Sprintf("DID not registered: %s", did), http.StatusNotFound)
		return
	}

	entries := make([]*didplc.LogEntry, 0, len(allEntries))
	for _, entry := range allEntries {
		entries = append(entries, &didplc.LogEntry{
			DID:       entry.DID,
			Operation: *entry.Op.AsOpEnum(),
			CID:       entry.OpCid,
			Nullified: entry.Nullified,
			CreatedAt: formatTimestamp(entry.CreatedAt),
		})
	}

	s.writeJSON(w, "application/json", entries)
}

// handleDIDLog handles GET /{did}/log - returns the full operation log
func (s *Server) handleDIDLog(w http.ResponseWriter, r *http.Request) {
	did := r.PathValue("did")
	ctx := r.Context()

	allEntries, err := s.store.GetAllEntries(ctx, did)
	if err != nil {
		s.writeJSONError(w, fmt.Sprintf("error fetching operation log: %v", err), http.StatusInternalServerError)
		return
	}

	// Filter out nullified operations
	operations := make([]*didplc.OpEnum, 0, len(allEntries))
	for _, entry := range allEntries {
		if !entry.Nullified {
			operations = append(operations, entry.Op.AsOpEnum())
		}
	}

	if len(operations) == 0 {
		s.writeJSONError(w, fmt.Sprintf("DID not registered: %s", did), http.StatusNotFound)
		return
	}

	s.writeJSON(w, "application/json", operations)
}

// handleDIDLogLast handles GET /{did}/log/last - returns the raw last operation
func (s *Server) handleDIDLogLast(w http.ResponseWriter, r *http.Request) {
	did := r.PathValue("did")
	ctx := r.Context()

	// Get the head CID for this DID
	head, err := s.store.GetLatest(ctx, did)
	if err != nil {
		s.writeJSONError(w, fmt.Sprintf("error fetching from store: %v", err), http.StatusInternalServerError)
		return
	}
	if head == nil {
		s.writeJSONError(w, fmt.Sprintf("DID not registered: %s", did), http.StatusNotFound)
		return
	}

	s.writeJSON(w, "application/json", head.Op.AsOpEnum())
}
