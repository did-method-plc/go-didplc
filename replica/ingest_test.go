package replica

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/did-method-plc/go-didplc/didplc"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Pure function tests ---

func TestBuildStreamURL_HTTPS(t *testing.T) {
	u, err := url.Parse("https://plc.directory")
	require.NoError(t, err)
	got := buildStreamURL(u, 42)
	assert.Equal(t, "wss://plc.directory/export/stream?cursor=42", got)
}

func TestBuildStreamURL_HTTP(t *testing.T) {
	u, err := url.Parse("http://localhost:8080")
	require.NoError(t, err)
	got := buildStreamURL(u, 0)
	assert.Equal(t, "ws://localhost:8080/export/stream?cursor=0", got)
}

func TestSleepCtx_Completes(t *testing.T) {
	ctx := context.Background()
	ok := sleepCtx(ctx, 1*time.Millisecond)
	assert.True(t, ok)
}

func TestSleepCtx_Cancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ok := sleepCtx(ctx, 10*time.Second)
	assert.False(t, ok)
}

func TestExportEntry_ToSequencedOp_Valid(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	priv, pubKey := generateKey(t)
	genesis, did := createGenesis(t, priv, []string{pubKey})

	entry := &ExportEntry{
		DID:       did,
		CID:       genesis.CID().String(),
		Seq:       1,
		CreatedAt: "2024-01-01T00:00:00Z",
		Operation: *genesis.AsOpEnum(),
		Type:      "sequenced_op",
	}

	seqop, err := entry.toSequencedOp(logger)
	require.NoError(t, err)
	require.NotNil(t, seqop)
	assert.Equal(t, did, seqop.DID)
	assert.Equal(t, genesis.CID().String(), seqop.CID)
	assert.Equal(t, int64(1), seqop.Seq)
	assert.Equal(t, time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC), seqop.CreatedAt)
}

func TestExportEntry_ToSequencedOp_WrongType(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	entry := &ExportEntry{
		DID:       "did:plc:test",
		CID:       "bafyreifakecid",
		Seq:       1,
		CreatedAt: "2024-01-01T00:00:00Z",
		Type:      "identity",
	}

	seqop, err := entry.toSequencedOp(logger)
	assert.NoError(t, err)
	assert.Nil(t, seqop)
}

func TestExportEntry_ToSequencedOp_BadTimestamp(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	priv, pubKey := generateKey(t)
	genesis, did := createGenesis(t, priv, []string{pubKey})

	entry := &ExportEntry{
		DID:       did,
		CID:       genesis.CID().String(),
		Seq:       1,
		CreatedAt: "not-a-timestamp",
		Operation: *genesis.AsOpEnum(),
		Type:      "sequenced_op",
	}

	seqop, err := entry.toSequencedOp(logger)
	assert.Error(t, err)
	assert.Nil(t, seqop)
	assert.Contains(t, err.Error(), "failed to parse timestamp")
}

func TestExportEntry_ToSequencedOp_NilOperation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	entry := &ExportEntry{
		DID:       "did:plc:test",
		CID:       "bafyreifakecid",
		Seq:       1,
		CreatedAt: "2024-01-01T00:00:00Z",
		Operation: didplc.OpEnum{}, // empty — AsOperation() returns nil
		Type:      "sequenced_op",
	}

	seqop, err := entry.toSequencedOp(logger)
	assert.NoError(t, err)
	assert.Nil(t, seqop)
}

// --- HTTP/WebSocket ingestion tests ---

// makeExportEntryJSON creates a JSON-encoded ExportEntry line for NDJSON responses.
// We build the JSON manually because OpEnum.MarshalJSON has a pointer receiver,
// which doesn't get invoked correctly when OpEnum is a value field in a struct.
func makeExportEntryJSON(t *testing.T, did, cid string, seq int64, createdAt time.Time, op didplc.Operation, typ string) []byte {
	t.Helper()
	opJSON, err := op.AsOpEnum().MarshalJSON()
	require.NoError(t, err)

	wrapper := struct {
		DID       string          `json:"did"`
		CID       string          `json:"cid"`
		Seq       int64           `json:"seq"`
		CreatedAt string          `json:"createdAt"`
		Operation json.RawMessage `json:"operation"`
		Type      string          `json:"type"`
	}{
		DID:       did,
		CID:       cid,
		Seq:       seq,
		CreatedAt: createdAt.Format(time.RFC3339),
		Operation: opJSON,
		Type:      typ,
	}
	data, err := json.Marshal(wrapper)
	require.NoError(t, err)
	return data
}

func TestIngestPaginated_BasicFlow(t *testing.T) {
	priv, pubKey := generateKey(t)
	genesis, did := createGenesis(t, priv, []string{pubKey})

	// Create a recent timestamp so ingestPaginated returns errCaughtUp
	recentTime := time.Now().Add(-30 * time.Minute)
	line := makeExportEntryJSON(t, did, genesis.CID().String(), 1, recentTime, genesis, "sequenced_op")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/export", r.URL.Path)
		w.Header().Set("Content-Type", "application/x-ndjson")
		fmt.Fprintf(w, "%s\n", line)
	}))
	defer ts.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ingestor, err := NewIngestor(newTestStore(t), NewReplicaState(), ts.URL, 0, 1, logger)
	require.NoError(t, err)

	ctx := context.Background()
	ops := make(chan *SequencedOp, 10)
	cursor := int64(0)

	err = ingestor.ingestPaginated(ctx, &cursor, ops)
	assert.ErrorIs(t, err, errCaughtUp)
	assert.Equal(t, int64(1), cursor)

	// Should have received the op
	require.Len(t, ops, 1)
	seqop := <-ops
	assert.Equal(t, did, seqop.DID)
}

func TestIngestPaginated_HTTPError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "internal error")
	}))
	defer ts.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ingestor, err := NewIngestor(newTestStore(t), NewReplicaState(), ts.URL, 0, 1, logger)
	require.NoError(t, err)

	ctx := context.Background()
	ops := make(chan *SequencedOp, 10)
	cursor := int64(0)

	err = ingestor.ingestPaginated(ctx, &cursor, ops)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "status 500")
}

func TestIngestPaginated_SkipsNonSequencedOp(t *testing.T) {
	priv, pubKey := generateKey(t)
	genesis, did := createGenesis(t, priv, []string{pubKey})

	recentTime := time.Now().Add(-30 * time.Minute)

	// One "identity" entry (should be skipped) and one "sequenced_op" entry
	identityLine, _ := json.Marshal(map[string]any{
		"did":       did,
		"cid":       "bafyreifakecid",
		"seq":       1,
		"createdAt": recentTime.Format(time.RFC3339),
		"type":      "identity",
	})
	seqopLine := makeExportEntryJSON(t, did, genesis.CID().String(), 2, recentTime, genesis, "sequenced_op")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ndjson")
		fmt.Fprintln(w, string(identityLine))
		fmt.Fprintf(w, "%s\n", seqopLine)
	}))
	defer ts.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ingestor, err := NewIngestor(newTestStore(t), NewReplicaState(), ts.URL, 0, 1, logger)
	require.NoError(t, err)

	ctx := context.Background()
	ops := make(chan *SequencedOp, 10)
	cursor := int64(0)

	err = ingestor.ingestPaginated(ctx, &cursor, ops)
	assert.ErrorIs(t, err, errCaughtUp)

	// Only the sequenced_op should have come through
	require.Len(t, ops, 1)
	seqop := <-ops
	assert.Equal(t, int64(2), seqop.Seq)
}

func TestIngestStream_BasicFlow(t *testing.T) {
	priv, pubKey := generateKey(t)
	genesis, did := createGenesis(t, priv, []string{pubKey})

	createdAt := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	entryBytes := makeExportEntryJSON(t, did, genesis.CID().String(), 5, createdAt, genesis, "sequenced_op")

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		conn.WriteMessage(websocket.TextMessage, entryBytes)
		// Close after sending one message to end the stream
		conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, "done"))
	}))
	defer ts.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ingestor, err := NewIngestor(newTestStore(t), NewReplicaState(), ts.URL, 0, 1, logger)
	require.NoError(t, err)

	// Override the parsed URL to use ws:// scheme for the test server
	wsURL := strings.Replace(ts.URL, "http://", "ws://", 1)
	ingestor.parsedDirectoryURL, _ = url.Parse(wsURL)

	ctx := context.Background()
	ops := make(chan *SequencedOp, 10)
	cursor := int64(0)

	// ingestStream will return an error when the WS closes
	err = ingestor.ingestStream(ctx, &cursor, ops)
	assert.Error(t, err) // normal close is still an error from ReadMessage perspective

	assert.Equal(t, int64(5), cursor)
	require.Len(t, ops, 1)
	seqop := <-ops
	assert.Equal(t, did, seqop.DID)
	assert.Equal(t, int64(5), seqop.Seq)
}

func TestIngestStream_OutdatedCursor(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, "OutdatedCursor"))
	}))
	defer ts.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ingestor, err := NewIngestor(newTestStore(t), NewReplicaState(), ts.URL, 0, 1, logger)
	require.NoError(t, err)

	wsURL := strings.Replace(ts.URL, "http://", "ws://", 1)
	ingestor.parsedDirectoryURL, _ = url.Parse(wsURL)

	ctx := context.Background()
	ops := make(chan *SequencedOp, 10)
	cursor := int64(0)

	err = ingestor.ingestStream(ctx, &cursor, ops)
	assert.ErrorIs(t, err, errOutdatedCursor)
}

func TestIngestStream_ContextCancellation(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		// Hold the connection open — don't send anything
		select {}
	}))
	defer ts.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ingestor, err := NewIngestor(newTestStore(t), NewReplicaState(), ts.URL, 0, 1, logger)
	require.NoError(t, err)

	wsURL := strings.Replace(ts.URL, "http://", "ws://", 1)
	ingestor.parsedDirectoryURL, _ = url.Parse(wsURL)

	ctx, cancel := context.WithCancel(context.Background())
	ops := make(chan *SequencedOp, 10)
	cursor := int64(0)

	done := make(chan error, 1)
	go func() {
		done <- ingestor.ingestStream(ctx, &cursor, ops)
	}()

	cancel()

	select {
	case err := <-done:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("ingestStream did not return promptly after context cancellation")
	}
}
