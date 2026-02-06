package replica

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/carlmjohnson/versioninfo"
	"github.com/did-method-plc/go-didplc/didplc"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

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
	fmt.Fprint(w, "hello plc replica\n")
}

// handleHealth handles GET /_health - returns version information
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"version": versioninfo.Short(),
	})
}

// writeJSONError writes a JSON error response
func writeJSONError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"message": message})
}

// handleDIDDoc handles GET /{did} - returns the DID document
func (s *Server) handleDIDDoc(w http.ResponseWriter, r *http.Request) {
	did := r.PathValue("did")
	ctx := r.Context()

	head, err := s.store.GetLatest(ctx, did)
	if err != nil {
		writeJSONError(w, fmt.Sprintf("error fetching head: %v", err), http.StatusInternalServerError)
		return
	}
	if head == nil {
		writeJSONError(w, fmt.Sprintf("DID not registered: %s", did), http.StatusNotFound)
		return
	}

	// Generate DID document
	doc, err := head.Op.Doc(did)
	if err != nil {
		writeJSONError(w, fmt.Sprintf("error generating DID document: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/did+json")
	if err := json.NewEncoder(w).Encode(doc); err != nil {
		writeJSONError(w, fmt.Sprintf("error encoding response: %v", err), http.StatusInternalServerError)
		return
	}
}

// handleDIDData handles GET /{did}/data - returns the latest operation data
func (s *Server) handleDIDData(w http.ResponseWriter, r *http.Request) {
	did := r.PathValue("did")
	ctx := r.Context()

	head, err := s.store.GetLatest(ctx, did)
	if err != nil {
		writeJSONError(w, fmt.Sprintf("error fetching head: %v", err), http.StatusInternalServerError)
		return
	}
	if head == nil {
		writeJSONError(w, fmt.Sprintf("DID not registered: %s", did), http.StatusNotFound)
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
		writeJSONError(w, fmt.Sprintf("DID not available: %s", did), http.StatusNotFound)
		return
	default:
		writeJSONError(w, "unknown operation type", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		writeJSONError(w, fmt.Sprintf("error encoding response: %v", err), http.StatusInternalServerError)
		return
	}
}

// handleDIDLogAudit handles GET /{did}/log/audit - returns the full audit log with metadata
func (s *Server) handleDIDLogAudit(w http.ResponseWriter, r *http.Request) {
	did := r.PathValue("did")
	ctx := r.Context()

	// Get the audit log (including nullified operations and metadata)
	entries, err := s.store.GetOperationLogAudit(ctx, did)
	if err != nil {
		writeJSONError(w, fmt.Sprintf("error fetching audit log: %v", err), http.StatusInternalServerError)
		return
	}

	if len(entries) == 0 {
		writeJSONError(w, fmt.Sprintf("DID not registered: %s", did), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(entries); err != nil {
		writeJSONError(w, fmt.Sprintf("error encoding response: %v", err), http.StatusInternalServerError)
		return
	}
}

// handleDIDLog handles GET /{did}/log - returns the full operation log
func (s *Server) handleDIDLog(w http.ResponseWriter, r *http.Request) {
	did := r.PathValue("did")
	ctx := r.Context()

	// Get the operation log (excluding nullified operations)
	operations, err := s.store.GetOperationLog(ctx, did)
	if err != nil {
		writeJSONError(w, fmt.Sprintf("error fetching operation log: %v", err), http.StatusInternalServerError)
		return
	}

	if len(operations) == 0 {
		writeJSONError(w, fmt.Sprintf("DID not registered: %s", did), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(operations); err != nil {
		writeJSONError(w, fmt.Sprintf("error encoding response: %v", err), http.StatusInternalServerError)
		return
	}
}

// handleDIDLogLast handles GET /{did}/log/last - returns the raw last operation
func (s *Server) handleDIDLogLast(w http.ResponseWriter, r *http.Request) {
	did := r.PathValue("did")
	ctx := r.Context()

	// Get the head CID for this DID
	head, err := s.store.GetLatest(ctx, did)
	if err != nil {
		writeJSONError(w, fmt.Sprintf("error fetching head: %v", err), http.StatusInternalServerError)
		return
	}
	if head == nil {
		writeJSONError(w, fmt.Sprintf("DID not registered: %s", did), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(head.Op.AsOpEnum()); err != nil {
		writeJSONError(w, fmt.Sprintf("error encoding response: %v", err), http.StatusInternalServerError)
		return
	}
}
