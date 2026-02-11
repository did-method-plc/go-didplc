package replica

import (
	"context"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/did-method-plc/go-didplc/didplc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helper: generate a key pair and return the private key and its did:key string
func generateKey(t *testing.T) (atcrypto.PrivateKey, string) {
	t.Helper()
	priv, err := atcrypto.GeneratePrivateKeyP256()
	require.NoError(t, err)
	pub, err := priv.PublicKey()
	require.NoError(t, err)
	return priv, pub.DIDKey()
}

// helper: create a signed genesis RegularOp and return it along with the computed DID
func createGenesis(t *testing.T, priv atcrypto.PrivateKey, rotationKeys []string) (*didplc.RegularOp, string) {
	t.Helper()
	pub, err := priv.PublicKey()
	require.NoError(t, err)
	op := &didplc.RegularOp{
		Type:         "plc_operation",
		RotationKeys: rotationKeys,
		VerificationMethods: map[string]string{
			"atproto": pub.DIDKey(),
		},
		AlsoKnownAs: []string{"at://test.example.com"},
		Services: map[string]didplc.OpService{
			"atproto_pds": {
				Type:     "AtprotoPersonalDataServer",
				Endpoint: "https://pds.example.com",
			},
		},
		Prev: nil,
	}
	require.NoError(t, op.Sign(priv))
	did, err := op.DID()
	require.NoError(t, err)
	return op, did
}

// helper: create a signed update RegularOp that chains after prevCID
func createUpdate(t *testing.T, priv atcrypto.PrivateKey, rotationKeys []string, prevCID string) *didplc.RegularOp {
	t.Helper()
	pub, err := priv.PublicKey()
	require.NoError(t, err)
	op := &didplc.RegularOp{
		Type:         "plc_operation",
		RotationKeys: rotationKeys,
		VerificationMethods: map[string]string{
			"atproto": pub.DIDKey(),
		},
		AlsoKnownAs: []string{"at://updated.example.com"},
		Services: map[string]didplc.OpService{
			"atproto_pds": {
				Type:     "AtprotoPersonalDataServer",
				Endpoint: "https://pds2.example.com",
			},
		},
		Prev: &prevCID,
	}
	require.NoError(t, op.Sign(priv))
	return op
}

// helper: commit a genesis op to the store and return its CID
func commitGenesis(t *testing.T, ctx context.Context, store didplc.OpStore, op *didplc.RegularOp, did string, createdAt time.Time) string {
	t.Helper()
	prepOp, err := didplc.VerifyOperation(ctx, store, did, op, createdAt)
	require.NoError(t, err)
	require.NoError(t, store.CommitOperations(ctx, []*didplc.PreparedOperation{prepOp}))
	return prepOp.OpCid
}

func TestValidateInner_GenesisValid(t *testing.T) {
	assert := assert.New(t)
	ctx := context.Background()
	store := didplc.NewMemOpStore()

	priv, pubKey := generateKey(t)
	op, did := createGenesis(t, priv, []string{pubKey})

	seqop := &SequencedOp{
		DID:       did,
		CID:       op.CID().String(),
		Operation: op,
		CreatedAt: time.Now(),
		Seq:       1,
	}

	prepOp, err := validateInner(ctx, seqop, store)
	assert.NoError(err)
	assert.Equal(did, prepOp.DID)
	assert.Equal(op.CID().String(), prepOp.OpCid)
	assert.Empty(prepOp.PrevHead)
	assert.Nil(prepOp.NullifiedOps)
}

func TestValidateInner_GenesisDIDMismatch(t *testing.T) {
	assert := assert.New(t)
	ctx := context.Background()
	store := didplc.NewMemOpStore()

	priv, pubKey := generateKey(t)
	op, _ := createGenesis(t, priv, []string{pubKey})

	seqop := &SequencedOp{
		DID:       "did:plc:wrong",
		CID:       op.CID().String(),
		Operation: op,
		CreatedAt: time.Now(),
		Seq:       1,
	}

	_, err := validateInner(ctx, seqop, store)
	assert.Error(err)
	assert.Contains(err.Error(), "genesis DID does not match")
}

func TestValidateInner_GenesisCIDMismatch(t *testing.T) {
	assert := assert.New(t)
	ctx := context.Background()
	store := didplc.NewMemOpStore()

	priv, pubKey := generateKey(t)
	op, did := createGenesis(t, priv, []string{pubKey})

	seqop := &SequencedOp{
		DID:       did,
		CID:       "bafyreiwrongcidvalue",
		Operation: op,
		CreatedAt: time.Now(),
		Seq:       1,
	}

	_, err := validateInner(ctx, seqop, store)
	assert.Error(err)
	assert.Contains(err.Error(), "inconsistent CID")
}

func TestValidateInner_GenesisDuplicateDID(t *testing.T) {
	assert := assert.New(t)
	ctx := context.Background()
	store := didplc.NewMemOpStore()

	priv, pubKey := generateKey(t)
	op, did := createGenesis(t, priv, []string{pubKey})
	now := time.Now()

	// commit the genesis first
	commitGenesis(t, ctx, store, op, did, now)

	// try to validate the same genesis again
	seqop := &SequencedOp{
		DID:       did,
		CID:       op.CID().String(),
		Operation: op,
		CreatedAt: now,
		Seq:       2,
	}

	_, err := validateInner(ctx, seqop, store)
	assert.Error(err)
	assert.Contains(err.Error(), "already exists")
}

func TestValidateInner_UpdateValid(t *testing.T) {
	assert := assert.New(t)
	ctx := context.Background()
	store := didplc.NewMemOpStore()

	priv, pubKey := generateKey(t)
	genesis, did := createGenesis(t, priv, []string{pubKey})
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	genesisCID := commitGenesis(t, ctx, store, genesis, did, t0)

	update := createUpdate(t, priv, []string{pubKey}, genesisCID)
	t1 := t0.Add(time.Hour)

	seqop := &SequencedOp{
		DID:       did,
		CID:       update.CID().String(),
		Operation: update,
		CreatedAt: t1,
		Seq:       2,
	}

	prepOp, err := validateInner(ctx, seqop, store)
	assert.NoError(err)
	assert.Equal(did, prepOp.DID)
	assert.Equal(genesisCID, prepOp.PrevHead)
	assert.Nil(prepOp.NullifiedOps)
}

func TestValidateInner_UpdateTimestampNotAdvanced(t *testing.T) {
	assert := assert.New(t)
	ctx := context.Background()
	store := didplc.NewMemOpStore()

	priv, pubKey := generateKey(t)
	genesis, did := createGenesis(t, priv, []string{pubKey})
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	genesisCID := commitGenesis(t, ctx, store, genesis, did, t0)

	update := createUpdate(t, priv, []string{pubKey}, genesisCID)

	// same timestamp as genesis — should fail
	seqop := &SequencedOp{
		DID:       did,
		CID:       update.CID().String(),
		Operation: update,
		CreatedAt: t0,
		Seq:       2,
	}

	_, err := validateInner(ctx, seqop, store)
	assert.Error(err)
	assert.Contains(err.Error(), "timestamp order")
}

func TestValidateInner_UpdateWrongSignatureKey(t *testing.T) {
	assert := assert.New(t)
	ctx := context.Background()
	store := didplc.NewMemOpStore()

	priv1, pubKey1 := generateKey(t)
	genesis, did := createGenesis(t, priv1, []string{pubKey1})
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	genesisCID := commitGenesis(t, ctx, store, genesis, did, t0)

	// sign update with a different key not in rotation keys
	priv2, _ := generateKey(t)
	update := createUpdate(t, priv2, []string{pubKey1}, genesisCID)
	t1 := t0.Add(time.Hour)

	seqop := &SequencedOp{
		DID:       did,
		CID:       update.CID().String(),
		Operation: update,
		CreatedAt: t1,
		Seq:       2,
	}

	_, err := validateInner(ctx, seqop, store)
	assert.Error(err)
	assert.Contains(err.Error(), "signature invalid")
}

func TestValidateInner_UpdateNonexistentDID(t *testing.T) {
	assert := assert.New(t)
	ctx := context.Background()
	store := didplc.NewMemOpStore()

	priv, pubKey := generateKey(t)
	prevCID := "bafyreifakecid"
	update := createUpdate(t, priv, []string{pubKey}, prevCID)

	seqop := &SequencedOp{
		DID:       "did:plc:nonexistent",
		CID:       update.CID().String(),
		Operation: update,
		CreatedAt: time.Now(),
		Seq:       1,
	}

	_, err := validateInner(ctx, seqop, store)
	assert.Error(err)
	assert.Contains(err.Error(), "DID not found")
}

func TestValidateInner_Nullification(t *testing.T) {
	assert := assert.New(t)
	ctx := context.Background()
	store := didplc.NewMemOpStore()

	// nullification requires two rotation keys: a recovery key (index 0)
	// and a regular key (index 1). The regular update uses key 1, which
	// trims allowed keys to [:1]. The nullification then uses key 0.
	privRecovery, pubKeyRecovery := generateKey(t)
	priv, pubKey := generateKey(t)
	rotationKeys := []string{pubKeyRecovery, pubKey}

	genesis, did := createGenesis(t, privRecovery, rotationKeys)
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	genesisCID := commitGenesis(t, ctx, store, genesis, did, t0)

	// create and commit a regular update signed by key at index 1
	update1 := createUpdate(t, priv, rotationKeys, genesisCID)
	t1 := t0.Add(time.Hour)
	prepOp1, err := didplc.VerifyOperation(ctx, store, did, update1, t1)
	require.NoError(t, err)
	require.Equal(t, 1, prepOp1.KeyIndex)
	require.NoError(t, store.CommitOperations(ctx, []*didplc.PreparedOperation{prepOp1}))

	// now create a nullification signed by the recovery key (index 0),
	// whose prev is the genesis (not update1) — this should nullify update1
	nullify := createUpdate(t, privRecovery, rotationKeys, genesisCID)
	t2 := t1.Add(time.Hour)

	seqop := &SequencedOp{
		DID:       did,
		CID:       nullify.CID().String(),
		Operation: nullify,
		CreatedAt: t2,
		Seq:       3,
	}

	prepOp, err := validateInner(ctx, seqop, store)
	assert.NoError(err)
	assert.Len(prepOp.NullifiedOps, 1)
	assert.Equal(update1.CID().String(), prepOp.NullifiedOps[0])
}

func TestValidateInner_NullificationTooSlow(t *testing.T) {
	assert := assert.New(t)
	ctx := context.Background()
	store := didplc.NewMemOpStore()

	privRecovery, pubKeyRecovery := generateKey(t)
	priv, pubKey := generateKey(t)
	rotationKeys := []string{pubKeyRecovery, pubKey}

	genesis, did := createGenesis(t, privRecovery, rotationKeys)
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	genesisCID := commitGenesis(t, ctx, store, genesis, did, t0)

	// create and commit a regular update signed by key at index 1
	update1 := createUpdate(t, priv, rotationKeys, genesisCID)
	t1 := t0.Add(time.Hour)
	prepOp1, err := didplc.VerifyOperation(ctx, store, did, update1, t1)
	require.NoError(t, err)
	require.NoError(t, store.CommitOperations(ctx, []*didplc.PreparedOperation{prepOp1}))

	// try nullification after 72h have passed since update1
	nullify := createUpdate(t, privRecovery, rotationKeys, genesisCID)
	tLate := t1.Add(73 * time.Hour)

	seqop := &SequencedOp{
		DID:       did,
		CID:       nullify.CID().String(),
		Operation: nullify,
		CreatedAt: tLate,
		Seq:       3,
	}

	_, err = validateInner(ctx, seqop, store)
	assert.Error(err)
	assert.Contains(err.Error(), "72h")
}

func TestValidateInner_Tombstone(t *testing.T) {
	assert := assert.New(t)
	ctx := context.Background()
	store := didplc.NewMemOpStore()

	priv, pubKey := generateKey(t)
	genesis, did := createGenesis(t, priv, []string{pubKey})
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	genesisCID := commitGenesis(t, ctx, store, genesis, did, t0)

	tombstone := &didplc.TombstoneOp{
		Type: "plc_tombstone",
		Prev: genesisCID,
	}
	require.NoError(t, tombstone.Sign(priv))
	t1 := t0.Add(time.Hour)

	seqop := &SequencedOp{
		DID:       did,
		CID:       tombstone.CID().String(),
		Operation: tombstone,
		CreatedAt: t1,
		Seq:       2,
	}

	prepOp, err := validateInner(ctx, seqop, store)
	assert.NoError(err)
	assert.Equal(did, prepOp.DID)
}

func TestValidateWorker_ValidOp(t *testing.T) {
	assert := assert.New(t)
	ctx := context.Background()
	store := didplc.NewMemOpStore()
	infl := NewInFlight(-1)

	priv, pubKey := generateKey(t)
	op, did := createGenesis(t, priv, []string{pubKey})

	seqops := make(chan *SequencedOp, 1)
	validatedOps := make(chan ValidatedOp, 1)

	seqop := &SequencedOp{
		DID:       did,
		CID:       op.CID().String(),
		Operation: op,
		CreatedAt: time.Now(),
		Seq:       1,
	}
	infl.AddInFlight(did, 1)
	seqops <- seqop
	close(seqops)

	ValidateWorker(ctx, seqops, validatedOps, infl, store)
	close(validatedOps)

	var results []ValidatedOp
	for vop := range validatedOps {
		results = append(results, vop)
	}

	assert.Len(results, 1)
	assert.Equal(int64(1), results[0].Seq)
	assert.Equal(did, results[0].PrepOp.DID)
}

func TestValidateWorker_InvalidOp(t *testing.T) {
	assert := assert.New(t)
	ctx := context.Background()
	store := didplc.NewMemOpStore()
	infl := NewInFlight(-1)

	priv, pubKey := generateKey(t)
	op, _ := createGenesis(t, priv, []string{pubKey})

	seqops := make(chan *SequencedOp, 1)
	validatedOps := make(chan ValidatedOp, 1)

	// wrong DID should cause validation failure
	seqop := &SequencedOp{
		DID:       "did:plc:wrong",
		CID:       op.CID().String(),
		Operation: op,
		CreatedAt: time.Now(),
		Seq:       1,
	}
	infl.AddInFlight("did:plc:wrong", 1)
	seqops <- seqop
	close(seqops)

	ValidateWorker(ctx, seqops, validatedOps, infl, store)
	close(validatedOps)

	var results []ValidatedOp
	for vop := range validatedOps {
		results = append(results, vop)
	}
	assert.Empty(results)

	// inflight should have been cleaned up
	assert.True(infl.AddInFlight("did:plc:wrong", 2), "DID should be available again after failed validation")
}

func TestCommitWorker_CommitsBatch(t *testing.T) {
	assert := assert.New(t)
	ctx := context.Background()
	store := didplc.NewMemOpStore()
	infl := NewInFlight(-1)

	priv, pubKey := generateKey(t)
	op, did := createGenesis(t, priv, []string{pubKey})
	now := time.Now()

	prepOp, err := didplc.VerifyOperation(ctx, store, did, op, now)
	require.NoError(t, err)

	validatedOps := make(chan ValidatedOp) // unbuffered: send blocks until worker reads
	flushCh := make(chan chan struct{})

	infl.AddInFlight(did, 1)

	workerDone := make(chan struct{})
	go func() {
		CommitWorker(ctx, validatedOps, infl, store, flushCh, NewReplicaState())
		close(workerDone)
	}()

	// send blocks until CommitWorker reads, so we know it has the op
	validatedOps <- ValidatedOp{Seq: 1, PrepOp: prepOp}

	// now flush — the op is guaranteed to be in the batch
	done := make(chan struct{})
	flushCh <- done
	<-done

	// verify it was committed
	head, err := store.GetLatest(ctx, did)
	assert.NoError(err)
	assert.Equal(op.CID().String(), head.OpCid)

	// close to stop the worker and wait for it to exit
	close(validatedOps)
	<-workerDone

	// inflight should have been cleaned up
	assert.True(infl.AddInFlight(did, 2))
}

func TestCommitWorker_FlushOnClose(t *testing.T) {
	assert := assert.New(t)
	ctx := context.Background()
	store := didplc.NewMemOpStore()
	infl := NewInFlight(-1)

	priv, pubKey := generateKey(t)
	op, did := createGenesis(t, priv, []string{pubKey})
	now := time.Now()

	prepOp, err := didplc.VerifyOperation(ctx, store, did, op, now)
	require.NoError(t, err)

	validatedOps := make(chan ValidatedOp, 1)
	flushCh := make(chan chan struct{})

	infl.AddInFlight(did, 1)
	validatedOps <- ValidatedOp{Seq: 1, PrepOp: prepOp}
	close(validatedOps)

	// run synchronously — CommitWorker returns when channel is closed
	CommitWorker(ctx, validatedOps, infl, store, flushCh, NewReplicaState())

	head, err := store.GetLatest(ctx, did)
	assert.NoError(err)
	assert.Equal(op.CID().String(), head.OpCid)
}

func TestEndToEnd_MultipleOps(t *testing.T) {
	assert := assert.New(t)
	ctx := context.Background()
	store := didplc.NewMemOpStore()
	infl := NewInFlight(-1)

	priv, pubKey := generateKey(t)
	genesis, did := createGenesis(t, priv, []string{pubKey})
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	// validate and commit genesis
	genesisPrepOp, err := didplc.VerifyOperation(ctx, store, did, genesis, t0)
	require.NoError(t, err)
	require.NoError(t, store.CommitOperations(ctx, []*didplc.PreparedOperation{genesisPrepOp}))
	genesisCID := genesisPrepOp.OpCid

	// create update
	update := createUpdate(t, priv, []string{pubKey}, genesisCID)
	t1 := t0.Add(time.Hour)

	seqops := make(chan *SequencedOp, 1)
	validatedOps := make(chan ValidatedOp, 1)
	flushCh := make(chan chan struct{}, 1)

	seqop := &SequencedOp{
		DID:       did,
		CID:       update.CID().String(),
		Operation: update,
		CreatedAt: t1,
		Seq:       2,
	}
	infl.AddInFlight(did, 2)
	seqops <- seqop
	close(seqops)

	// run validate worker
	ValidateWorker(ctx, seqops, validatedOps, infl, store)
	close(validatedOps)

	// collect validated ops and commit
	var validated []ValidatedOp
	for vop := range validatedOps {
		validated = append(validated, vop)
	}
	require.Len(t, validated, 1)

	// commit via store directly
	require.NoError(t, store.CommitOperations(ctx, []*didplc.PreparedOperation{validated[0].PrepOp}))
	infl.RemoveInFlight(did, 2)
	_ = flushCh // unused in this test path

	// verify head updated
	head, err := store.GetLatest(ctx, did)
	assert.NoError(err)
	assert.Equal(update.CID().String(), head.OpCid)
}

func TestValidateInner_RotationKeyChange(t *testing.T) {
	assert := assert.New(t)
	ctx := context.Background()
	store := didplc.NewMemOpStore()

	priv1, pubKey1 := generateKey(t)
	priv2, pubKey2 := generateKey(t)

	// genesis with both keys as rotation keys
	genesis, did := createGenesis(t, priv1, []string{pubKey1, pubKey2})
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	genesisCID := commitGenesis(t, ctx, store, genesis, did, t0)

	// update signed by key2 (second rotation key) — should succeed
	update := createUpdate(t, priv2, []string{pubKey2}, genesisCID)
	t1 := t0.Add(time.Hour)

	seqop := &SequencedOp{
		DID:       did,
		CID:       update.CID().String(),
		Operation: update,
		CreatedAt: t1,
		Seq:       2,
	}

	prepOp, err := validateInner(ctx, seqop, store)
	assert.NoError(err)
	assert.Equal(1, prepOp.KeyIndex, "should be signed by second rotation key")
}
