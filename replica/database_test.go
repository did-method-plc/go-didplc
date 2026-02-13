package replica

import (
	"context"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/did-method-plc/go-didplc/didplc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
)

func newTestStore(t *testing.T) *GormOpStore {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	if dbURL := os.Getenv("DATABASE_URL"); dbURL != "" {
		store, err := NewGormOpStore(dbURL, logger)
		require.NoError(t, err)
		// Truncate tables for test isolation
		require.NoError(t, store.db.Exec("TRUNCATE operations, heads, host_cursors").Error)
		t.Cleanup(func() {
			store.db.Exec("TRUNCATE operations, heads, host_cursors")
			sqlDB, _ := store.db.DB()
			sqlDB.Close()
		})
		return store
	}

	store, err := NewGormOpStoreWithDialector(sqlite.Open(":memory:"), logger)
	require.NoError(t, err)
	sqlDB, err := store.db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { sqlDB.Close() })
	return store
}

func TestGormOpStore_GetLatest_Empty(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	entry, err := store.GetLatest(ctx, "did:plc:nonexistent")
	assert.NoError(t, err)
	assert.Nil(t, entry)
}

func TestGormOpStore_GetLatest_AfterGenesis(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	priv, pubKey := generateKey(t)
	genesis, did := createGenesis(t, priv, []string{pubKey})
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	genesisCID := commitGenesis(t, ctx, store, genesis, did, t0)

	entry, err := store.GetLatest(ctx, did)
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Equal(t, did, entry.DID)
	assert.Equal(t, genesisCID, entry.OpCid)
	assert.False(t, entry.Nullified)
}

func TestGormOpStore_GetLatest_AfterUpdate(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	priv, pubKey := generateKey(t)
	genesis, did := createGenesis(t, priv, []string{pubKey})
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	genesisCID := commitGenesis(t, ctx, store, genesis, did, t0)

	update := createUpdate(t, priv, []string{pubKey}, genesisCID)
	t1 := t0.Add(time.Hour)
	prepOp, err := didplc.VerifyOperation(ctx, store, did, update, t1)
	require.NoError(t, err)
	require.NoError(t, store.CommitOperations(ctx, []*didplc.PreparedOperation{prepOp}))

	entry, err := store.GetLatest(ctx, did)
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Equal(t, update.CID().String(), entry.OpCid)
}

func TestGormOpStore_GetEntry_Found(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	priv, pubKey := generateKey(t)
	genesis, did := createGenesis(t, priv, []string{pubKey})
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	genesisCID := commitGenesis(t, ctx, store, genesis, did, t0)

	entry, err := store.GetEntry(ctx, did, genesisCID)
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Equal(t, did, entry.DID)
	assert.Equal(t, genesisCID, entry.OpCid)
}

func TestGormOpStore_GetEntry_NotFound(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	entry, err := store.GetEntry(ctx, "did:plc:nonexistent", "bafyreifakecid")
	assert.NoError(t, err)
	assert.Nil(t, entry)
}

func TestGormOpStore_GetAllEntries_Ordered(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	priv, pubKey := generateKey(t)
	genesis, did := createGenesis(t, priv, []string{pubKey})
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	genesisCID := commitGenesis(t, ctx, store, genesis, did, t0)

	update := createUpdate(t, priv, []string{pubKey}, genesisCID)
	t1 := t0.Add(time.Hour)
	prepOp, err := didplc.VerifyOperation(ctx, store, did, update, t1)
	require.NoError(t, err)
	require.NoError(t, store.CommitOperations(ctx, []*didplc.PreparedOperation{prepOp}))

	entries, err := store.GetAllEntries(ctx, did)
	require.NoError(t, err)
	require.Len(t, entries, 2)
	assert.Equal(t, genesisCID, entries[0].OpCid, "first entry should be genesis (earlier created_at)")
	assert.Equal(t, update.CID().String(), entries[1].OpCid, "second entry should be update")
}

func TestGormOpStore_GetAllEntries_Empty(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	entries, err := store.GetAllEntries(ctx, "did:plc:nonexistent")
	assert.NoError(t, err)
	assert.Empty(t, entries)
}

func TestGormOpStore_CommitGenesis_DuplicateDID(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	priv, pubKey := generateKey(t)
	genesis, did := createGenesis(t, priv, []string{pubKey})
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	// Commit genesis the first time
	prepOp, err := didplc.VerifyOperation(ctx, store, did, genesis, t0)
	require.NoError(t, err)
	require.NoError(t, store.CommitOperations(ctx, []*didplc.PreparedOperation{prepOp}))

	// Create a second, different genesis op for the same DID.
	// It must have a different CID to avoid the operations UNIQUE constraint,
	// so the Head UNIQUE constraint (ErrHeadMismatch) is the one that fires.
	genesis2, _ := createGenesis(t, priv, []string{pubKey})
	prepOp2 := &didplc.PreparedOperation{
		DID:       did,
		PrevHead:  "",
		CreatedAt: t0.Add(time.Second),
		Op:        genesis2,
		OpCid:     genesis2.CID().String(),
	}
	err = store.CommitOperations(ctx, []*didplc.PreparedOperation{prepOp2})
	assert.ErrorIs(t, err, didplc.ErrHeadMismatch)
}

func TestGormOpStore_CommitUpdate_HeadMismatch(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	priv, pubKey := generateKey(t)
	genesis, did := createGenesis(t, priv, []string{pubKey})
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	genesisCID := commitGenesis(t, ctx, store, genesis, did, t0)

	// Create a valid update
	update := createUpdate(t, priv, []string{pubKey}, genesisCID)
	t1 := t0.Add(time.Hour)
	prepOp, err := didplc.VerifyOperation(ctx, store, did, update, t1)
	require.NoError(t, err)

	// Tamper with PrevHead to simulate a concurrent modification
	prepOp.PrevHead = "bafyreiwrongprevhead"
	err = store.CommitOperations(ctx, []*didplc.PreparedOperation{prepOp})
	assert.ErrorIs(t, err, didplc.ErrHeadMismatch)
}

func TestGormOpStore_CommitUpdate_InterleavedHeadMismatch(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	priv, pubKey := generateKey(t)
	genesis, did := createGenesis(t, priv, []string{pubKey})
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	genesisCID := commitGenesis(t, ctx, store, genesis, did, t0)

	// Both updates chain off genesis (same PrevHead)
	updateA := createUpdate(t, priv, []string{pubKey}, genesisCID)
	updateB := createUpdate(t, priv, []string{pubKey}, genesisCID)

	// Verify both while head is still genesis
	prepA, err := didplc.VerifyOperation(ctx, store, did, updateA, t0.Add(1*time.Hour))
	require.NoError(t, err)
	prepB, err := didplc.VerifyOperation(ctx, store, did, updateB, t0.Add(2*time.Hour))
	require.NoError(t, err)

	// Commit A — succeeds, advances head past genesis
	require.NoError(t, store.CommitOperations(ctx, []*didplc.PreparedOperation{prepA}))

	// Commit B — should fail: its PrevHead is genesis but head is now A
	err = store.CommitOperations(ctx, []*didplc.PreparedOperation{prepB})
	assert.ErrorIs(t, err, didplc.ErrHeadMismatch)
}

func TestGormOpStore_CommitNullification(t *testing.T) {
	store := newTestStore(t)
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

	// Nullification signed by recovery key (prev = genesis)
	nullify := createUpdate(t, privRecovery, rotationKeys, genesisCID)
	t2 := t1.Add(time.Hour)
	prepOp2, err := didplc.VerifyOperation(ctx, store, did, nullify, t2)
	require.NoError(t, err)
	require.NoError(t, store.CommitOperations(ctx, []*didplc.PreparedOperation{prepOp2}))

	// Verify nullification state via GetAllEntries
	entries, err := store.GetAllEntries(ctx, did)
	require.NoError(t, err)
	require.Len(t, entries, 3)

	// The update (index 1) should be nullified
	assert.False(t, entries[0].Nullified, "genesis should not be nullified")
	assert.True(t, entries[1].Nullified, "update should be nullified")
	assert.False(t, entries[2].Nullified, "nullification op should not be nullified")
}

func TestGormOpStore_CommitBatch_MultipleDIDs(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Create two independent DIDs
	priv1, pubKey1 := generateKey(t)
	genesis1, did1 := createGenesis(t, priv1, []string{pubKey1})
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	priv2, pubKey2 := generateKey(t)
	genesis2, did2 := createGenesis(t, priv2, []string{pubKey2})

	prepOp1, err := didplc.VerifyOperation(ctx, store, did1, genesis1, t0)
	require.NoError(t, err)
	prepOp2, err := didplc.VerifyOperation(ctx, store, did2, genesis2, t0)
	require.NoError(t, err)

	// Commit both in a single batch
	require.NoError(t, store.CommitOperations(ctx, []*didplc.PreparedOperation{prepOp1, prepOp2}))

	// Verify both DIDs exist
	entry1, err := store.GetLatest(ctx, did1)
	require.NoError(t, err)
	assert.NotNil(t, entry1)
	assert.Equal(t, did1, entry1.DID)

	entry2, err := store.GetLatest(ctx, did2)
	require.NoError(t, err)
	assert.NotNil(t, entry2)
	assert.Equal(t, did2, entry2.DID)
}

func TestGormOpStore_CursorRoundTrip(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Default cursor for unknown host
	seq, err := store.GetCursor(ctx, "plc.directory")
	assert.NoError(t, err)
	assert.Equal(t, int64(0), seq)

	// Put and get
	require.NoError(t, store.PutCursor(ctx, "plc.directory", 42))
	seq, err = store.GetCursor(ctx, "plc.directory")
	assert.NoError(t, err)
	assert.Equal(t, int64(42), seq)

	// Upsert (update existing)
	require.NoError(t, store.PutCursor(ctx, "plc.directory", 100))
	seq, err = store.GetCursor(ctx, "plc.directory")
	assert.NoError(t, err)
	assert.Equal(t, int64(100), seq)
}

func TestGormOpStore_CursorMultipleHosts(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, store.PutCursor(ctx, "host-a", 10))
	require.NoError(t, store.PutCursor(ctx, "host-b", 20))

	seqA, err := store.GetCursor(ctx, "host-a")
	assert.NoError(t, err)
	assert.Equal(t, int64(10), seqA)

	seqB, err := store.GetCursor(ctx, "host-b")
	assert.NoError(t, err)
	assert.Equal(t, int64(20), seqB)
}

func TestGormOpStore_AllowedKeysCount_AfterUpdate(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	priv1, pubKey1 := generateKey(t)
	_, pubKey2 := generateKey(t)
	rotationKeys := []string{pubKey1, pubKey2}

	genesis, did := createGenesis(t, priv1, rotationKeys)
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	genesisCID := commitGenesis(t, ctx, store, genesis, did, t0)

	// Update signed by key at index 1 (priv1 is at index 0 in rotationKeys,
	// but we sign with priv1 which matches pubKey1 at index 0)
	update := createUpdate(t, priv1, rotationKeys, genesisCID)
	t1 := t0.Add(time.Hour)
	prepOp, err := didplc.VerifyOperation(ctx, store, did, update, t1)
	require.NoError(t, err)
	require.NoError(t, store.CommitOperations(ctx, []*didplc.PreparedOperation{prepOp}))

	// The previous (genesis) op should have allowed_keys_count set to KeyIndex
	var genesisRec OperationRecord
	require.NoError(t, store.db.Where("did = ? AND cid = ?", did, genesisCID).Take(&genesisRec).Error)
	assert.Equal(t, prepOp.KeyIndex, genesisRec.AllowedKeysCount,
		"genesis op's allowed_keys_count should be updated to the signing key index")
}

func TestGormOpStore_CommitBatch_PartialFailureRollback(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	// DID-A: fresh genesis, will succeed on its own
	privA, pubKeyA := generateKey(t)
	genesisA, didA := createGenesis(t, privA, []string{pubKeyA})
	prepA, err := didplc.VerifyOperation(ctx, store, didA, genesisA, t0)
	require.NoError(t, err)

	// DID-B: commit genesis, then prepare two competing updates while head is still genesis
	privB, pubKeyB := generateKey(t)
	genesisB, didB := createGenesis(t, privB, []string{pubKeyB})
	genesisBCID := commitGenesis(t, ctx, store, genesisB, didB, t0)

	updateB1 := createUpdate(t, privB, []string{pubKeyB}, genesisBCID)
	updateB2 := createUpdate(t, privB, []string{pubKeyB}, genesisBCID)
	prepB1, err := didplc.VerifyOperation(ctx, store, didB, updateB1, t0.Add(1*time.Hour))
	require.NoError(t, err)
	prepB2, err := didplc.VerifyOperation(ctx, store, didB, updateB2, t0.Add(2*time.Hour))
	require.NoError(t, err)

	// Advance DID-B's head — prepB2's PrevHead is now stale
	require.NoError(t, store.CommitOperations(ctx, []*didplc.PreparedOperation{prepB1}))

	// Batch: A (would succeed) then B2 (will fail with head mismatch)
	err = store.CommitOperations(ctx, []*didplc.PreparedOperation{prepA, prepB2})
	assert.Error(t, err, "batch should fail due to DID-B head mismatch")

	// DID-A must NOT have been committed — transaction should have rolled back
	entryA, err := store.GetLatest(ctx, didA)
	assert.NoError(t, err)
	assert.Nil(t, entryA, "DID-A should not exist: batch rollback must be atomic")
}

func TestGormOpStore_ConcurrentUpdateRace(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	priv, pubKey := generateKey(t)
	genesis, did := createGenesis(t, priv, []string{pubKey})
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	genesisCID := commitGenesis(t, ctx, store, genesis, did, t0)

	// Prepare two updates both chaining off genesis
	updateA := createUpdate(t, priv, []string{pubKey}, genesisCID)
	prepA, err := didplc.VerifyOperation(ctx, store, did, updateA, t0.Add(1*time.Hour))
	require.NoError(t, err)

	updateB := createUpdate(t, priv, []string{pubKey}, genesisCID)
	prepB, err := didplc.VerifyOperation(ctx, store, did, updateB, t0.Add(2*time.Hour))
	require.NoError(t, err)

	// Race them
	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		errs[0] = store.CommitOperations(ctx, []*didplc.PreparedOperation{prepA})
	}()
	go func() {
		defer wg.Done()
		errs[1] = store.CommitOperations(ctx, []*didplc.PreparedOperation{prepB})
	}()
	wg.Wait()

	// Exactly one should succeed, the other should fail
	succeeded := 0
	for _, err := range errs {
		if err == nil {
			succeeded++
		}
	}
	assert.Equal(t, 1, succeeded, "exactly one concurrent commit should win")

	// Head should be consistent — points to whichever update won
	head, err := store.GetLatest(ctx, did)
	require.NoError(t, err)
	require.NotNil(t, head)
	assert.True(t,
		head.OpCid == updateA.CID().String() || head.OpCid == updateB.CID().String(),
		"head should be one of the two updates")
}

func TestGormOpStore_ConcurrentGenesisRace(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// The same signed genesis op submitted twice concurrently.
	// The PLC DID is derived from the signed genesis bytes, so two different
	// signatures produce two different DIDs — the only realistic duplicate
	// genesis scenario is the exact same op arriving twice.
	priv, pubKey := generateKey(t)
	genesis, did := createGenesis(t, priv, []string{pubKey})

	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	prep, err := didplc.VerifyOperation(ctx, store, did, genesis, t0)
	require.NoError(t, err)

	// Race the same PreparedOperation from two goroutines
	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		errs[0] = store.CommitOperations(ctx, []*didplc.PreparedOperation{prep})
	}()
	go func() {
		defer wg.Done()
		errs[1] = store.CommitOperations(ctx, []*didplc.PreparedOperation{prep})
	}()
	wg.Wait()

	// Exactly one should succeed
	succeeded := 0
	for _, err := range errs {
		if err == nil {
			succeeded++
		}
	}
	assert.Equal(t, 1, succeeded, "exactly one concurrent genesis should win")

	// DID should exist with exactly one entry
	entries, err := store.GetAllEntries(ctx, did)
	require.NoError(t, err)
	assert.Len(t, entries, 1, "should have exactly one genesis op")
}
