package replica

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/did-method-plc/go-didplc/didplc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
)

func newTestServer(t *testing.T) (http.Handler, *DBOpStore) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := NewDBOpStoreWithDialector(sqlite.Open(":memory:"), logger)
	require.NoError(t, err)
	sqlDB, err := store.db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { sqlDB.Close() })

	s := NewServer(store, ":0", logger)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{did}/log/audit", s.handleDIDLogAudit)
	mux.HandleFunc("GET /{did}/log/last", s.handleDIDLogLast)
	mux.HandleFunc("GET /{did}/log", s.handleDIDLog)
	mux.HandleFunc("GET /{did}/data", s.handleDIDData)
	mux.HandleFunc("GET /{did}", s.handleDIDDoc)
	mux.HandleFunc("GET /{$}", s.handleIndex)
	return mux, store
}

func TestHandleIndex(t *testing.T) {
	handler, _ := newTestServer(t)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/plain", w.Header().Get("Content-Type"))
	assert.NotEmpty(t, w.Body.String())
}

func TestHandleDIDDoc(t *testing.T) {
	handler, store := newTestServer(t)
	ctx := context.Background()

	priv, pubKey := generateKey(t)
	genesis, did := createGenesis(t, priv, []string{pubKey})
	commitGenesis(t, ctx, store, genesis, did, time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/"+did, nil))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/did+json", w.Header().Get("Content-Type"))

	var doc didplc.Doc
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &doc))
	assert.Equal(t, did, doc.ID)
	assert.Contains(t, doc.AlsoKnownAs, "at://test.example.com")
	assert.NotEmpty(t, doc.VerificationMethod)
	assert.NotEmpty(t, doc.Service)
}

func TestHandleDIDDoc_NotFound(t *testing.T) {
	handler, _ := newTestServer(t)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/did:plc:nonexistent", nil))

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
}

func TestHandleDIDData(t *testing.T) {
	handler, store := newTestServer(t)
	ctx := context.Background()

	priv, pubKey := generateKey(t)
	genesis, did := createGenesis(t, priv, []string{pubKey})
	commitGenesis(t, ctx, store, genesis, did, time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/"+did+"/data", nil))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var resp DIDDataResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, did, resp.DID)
	assert.Equal(t, []string{pubKey}, resp.RotationKeys)
	assert.Contains(t, resp.AlsoKnownAs, "at://test.example.com")
	assert.Contains(t, resp.Services, "atproto_pds")
}

func TestHandleDIDData_NotFound(t *testing.T) {
	handler, _ := newTestServer(t)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/did:plc:nonexistent/data", nil))

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleDIDData_Tombstone(t *testing.T) {
	handler, store := newTestServer(t)
	ctx := context.Background()

	priv, pubKey := generateKey(t)
	genesis, did := createGenesis(t, priv, []string{pubKey})
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	genesisCID := commitGenesis(t, ctx, store, genesis, did, t0)

	tombstone := &didplc.TombstoneOp{Type: "plc_tombstone", Prev: genesisCID}
	require.NoError(t, tombstone.Sign(priv))
	prepOp, err := didplc.VerifyOperation(ctx, store, did, tombstone, t0.Add(time.Hour))
	require.NoError(t, err)
	require.NoError(t, store.CommitOperations(ctx, []*didplc.PreparedOperation{prepOp}))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/"+did+"/data", nil))

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleDIDData_AfterUpdate(t *testing.T) {
	handler, store := newTestServer(t)
	ctx := context.Background()

	priv, pubKey := generateKey(t)
	genesis, did := createGenesis(t, priv, []string{pubKey})
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	genesisCID := commitGenesis(t, ctx, store, genesis, did, t0)

	update := createUpdate(t, priv, []string{pubKey}, genesisCID)
	prepOp, err := didplc.VerifyOperation(ctx, store, did, update, t0.Add(time.Hour))
	require.NoError(t, err)
	require.NoError(t, store.CommitOperations(ctx, []*didplc.PreparedOperation{prepOp}))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/"+did+"/data", nil))

	assert.Equal(t, http.StatusOK, w.Code)

	var resp DIDDataResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, did, resp.DID)
	assert.Contains(t, resp.AlsoKnownAs, "at://updated.example.com")
}

func TestHandleDIDLog(t *testing.T) {
	handler, store := newTestServer(t)
	ctx := context.Background()

	priv, pubKey := generateKey(t)
	genesis, did := createGenesis(t, priv, []string{pubKey})
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	genesisCID := commitGenesis(t, ctx, store, genesis, did, t0)

	update := createUpdate(t, priv, []string{pubKey}, genesisCID)
	prepOp, err := didplc.VerifyOperation(ctx, store, did, update, t0.Add(time.Hour))
	require.NoError(t, err)
	require.NoError(t, store.CommitOperations(ctx, []*didplc.PreparedOperation{prepOp}))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/"+did+"/log", nil))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var ops []didplc.OpEnum
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &ops))
	assert.Len(t, ops, 2)
}

func TestHandleDIDLog_NotFound(t *testing.T) {
	handler, _ := newTestServer(t)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/did:plc:nonexistent/log", nil))

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleDIDLog_ExcludesNullified(t *testing.T) {
	handler, store := newTestServer(t)
	ctx := context.Background()

	privRecovery, pubKeyRecovery := generateKey(t)
	priv, pubKey := generateKey(t)
	rotationKeys := []string{pubKeyRecovery, pubKey}

	genesis, did := createGenesis(t, privRecovery, rotationKeys)
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	genesisCID := commitGenesis(t, ctx, store, genesis, did, t0)

	// Regular update signed by key at index 1
	update := createUpdate(t, priv, rotationKeys, genesisCID)
	t1 := t0.Add(time.Hour)
	prepOp1, err := didplc.VerifyOperation(ctx, store, did, update, t1)
	require.NoError(t, err)
	require.NoError(t, store.CommitOperations(ctx, []*didplc.PreparedOperation{prepOp1}))

	// Nullification signed by recovery key (prev = genesis, not update)
	nullify := createUpdate(t, privRecovery, rotationKeys, genesisCID)
	t2 := t1.Add(time.Hour)
	prepOp2, err := didplc.VerifyOperation(ctx, store, did, nullify, t2)
	require.NoError(t, err)
	require.NoError(t, store.CommitOperations(ctx, []*didplc.PreparedOperation{prepOp2}))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/"+did+"/log", nil))

	assert.Equal(t, http.StatusOK, w.Code)

	var ops []didplc.OpEnum
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &ops))
	assert.Len(t, ops, 2, "should have genesis + nullification, excluding the nullified update")
}

func TestHandleDIDLogAudit(t *testing.T) {
	handler, store := newTestServer(t)
	ctx := context.Background()

	privRecovery, pubKeyRecovery := generateKey(t)
	priv, pubKey := generateKey(t)
	rotationKeys := []string{pubKeyRecovery, pubKey}

	genesis, did := createGenesis(t, privRecovery, rotationKeys)
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	genesisCID := commitGenesis(t, ctx, store, genesis, did, t0)

	// Regular update signed by key at index 1
	update := createUpdate(t, priv, rotationKeys, genesisCID)
	t1 := t0.Add(time.Hour)
	prepOp1, err := didplc.VerifyOperation(ctx, store, did, update, t1)
	require.NoError(t, err)
	require.NoError(t, store.CommitOperations(ctx, []*didplc.PreparedOperation{prepOp1}))

	// Nullification signed by recovery key
	nullify := createUpdate(t, privRecovery, rotationKeys, genesisCID)
	t2 := t1.Add(time.Hour)
	prepOp2, err := didplc.VerifyOperation(ctx, store, did, nullify, t2)
	require.NoError(t, err)
	require.NoError(t, store.CommitOperations(ctx, []*didplc.PreparedOperation{prepOp2}))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/"+did+"/log/audit", nil))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var entries []didplc.LogEntry
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &entries))
	assert.Len(t, entries, 3, "audit log includes all ops including nullified")

	nullifiedCount := 0
	for _, e := range entries {
		if e.Nullified {
			nullifiedCount++
		}
	}
	assert.Equal(t, 1, nullifiedCount)
}

func TestHandleDIDLogAudit_NotFound(t *testing.T) {
	handler, _ := newTestServer(t)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/did:plc:nonexistent/log/audit", nil))

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleDIDLogLast(t *testing.T) {
	handler, store := newTestServer(t)
	ctx := context.Background()

	priv, pubKey := generateKey(t)
	genesis, did := createGenesis(t, priv, []string{pubKey})
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	genesisCID := commitGenesis(t, ctx, store, genesis, did, t0)

	update := createUpdate(t, priv, []string{pubKey}, genesisCID)
	prepOp, err := didplc.VerifyOperation(ctx, store, did, update, t0.Add(time.Hour))
	require.NoError(t, err)
	require.NoError(t, store.CommitOperations(ctx, []*didplc.PreparedOperation{prepOp}))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/"+did+"/log/last", nil))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var opEnum didplc.OpEnum
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &opEnum))
	assert.NotNil(t, opEnum.Regular)
	assert.NotNil(t, opEnum.Regular.Prev, "last op should be the update, not genesis")
}

func TestHandleDIDLogLast_GenesisOnly(t *testing.T) {
	handler, store := newTestServer(t)
	ctx := context.Background()

	priv, pubKey := generateKey(t)
	genesis, did := createGenesis(t, priv, []string{pubKey})
	commitGenesis(t, ctx, store, genesis, did, time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/"+did+"/log/last", nil))

	assert.Equal(t, http.StatusOK, w.Code)

	var opEnum didplc.OpEnum
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &opEnum))
	assert.NotNil(t, opEnum.Regular)
	assert.Nil(t, opEnum.Regular.Prev, "genesis op has no prev")
}

func TestHandleDIDLogLast_NotFound(t *testing.T) {
	handler, _ := newTestServer(t)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/did:plc:nonexistent/log/last", nil))

	assert.Equal(t, http.StatusNotFound, w.Code)
}
