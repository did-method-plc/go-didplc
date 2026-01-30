package didplc

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type OpStatus struct {
	DID         string
	CreatedAt   time.Time
	Nullified   bool
	LastChild   string   // CID of most recent operation with `prev` referencing this op
	AllowedKeys []string // the set of public did:keys currently allowed to update from this op
}

// PreparedOperation contains all the information needed to commit a validated operation.
type PreparedOperation struct {
	DID          string
	PrevHead     string
	NullifiedOps []string // CIDs of any operations being nullified
	KeyIndex     int
	CreatedAt    time.Time
	Op           Operation
	OpCid        string
}

type OpStore interface {
	// GetHead returns the CID of the most recent valid operation for a DID.
	// Returns empty string if the DID does not exist.
	GetHead(ctx context.Context, did string) (string, error)

	// GetMetadata returns metadata about a specific operation.
	// Returns an error if the operation does not exist.
	GetMetadata(ctx context.Context, did string, cid string) (*OpStatus, error)

	// GetOperation returns the operation data for a specific DID and CID.
	// Returns an error if the operation does not exist.
	GetOperation(ctx context.Context, did string, cid string) (Operation, error)

	// CommitOperations atomically commits a batch of prepared operations to the store.
	// All operations in the batch are committed or none are (all-or-nothing).

	// For each PreparedOperation, `prevHead` MUST match the head value returned by an earlier call to GetHead.
	// If multiple updates to the same DID are attempted concurrently, one will return an error due to head mismatch.
	CommitOperations(ctx context.Context, ops []*PreparedOperation) error
}

type InMemoryOpStore struct {
	head       map[string]string    // DID -> CID (head)
	opStatus   map[string]*OpStatus // CID -> OpStatus (metadata)
	operations map[string]Operation // CID -> Operation
	lock       sync.RWMutex
}

func NewInMemoryOpStore() *InMemoryOpStore {
	return &InMemoryOpStore{
		head:       make(map[string]string),
		opStatus:   make(map[string]*OpStatus),
		operations: make(map[string]Operation),
	}
}

// GetHead returns the CID of the most recent valid operation for a DID.
// Returns empty string if the DID does not exist.
func (store *InMemoryOpStore) GetHead(ctx context.Context, did string) (string, error) {
	store.lock.RLock()
	defer store.lock.RUnlock()

	head, exists := store.head[did]
	if !exists {
		return "", nil
	}
	return head, nil
}

// GetMetadata returns metadata about a specific operation.
// Returns an error if the operation does not exist or belongs to a different DID.
// The returned OpStatus is a copy and safe for mutation.
func (store *InMemoryOpStore) GetMetadata(ctx context.Context, did string, cid string) (*OpStatus, error) {
	store.lock.RLock()
	defer store.lock.RUnlock()

	status, exists := store.opStatus[cid]
	if !exists {
		return nil, fmt.Errorf("operation not found")
	}

	if status.DID != did {
		// This implies an implementation bug, should be unreachable
		return nil, fmt.Errorf("operation belongs to a different DID")
	}

	return status, nil
}

// GetOperation returns the operation data for a specific DID and CID.
// Returns an error if the operation does not exist or belongs to a different DID.
func (store *InMemoryOpStore) GetOperation(ctx context.Context, did string, cid string) (Operation, error) {
	store.lock.RLock()
	defer store.lock.RUnlock()

	op, exists := store.operations[cid]
	if !exists {
		return nil, fmt.Errorf("operation not found")
	}

	// Verify it belongs to the correct DID
	status, exists := store.opStatus[cid]
	if !exists {
		// This implies an implementation bug, should be unreachable
		return nil, fmt.Errorf("operation metadata not found")
	}

	if status.DID != did {
		// This implies an implementation bug, should be unreachable
		return nil, fmt.Errorf("operation belongs to a different DID")
	}

	return op, nil
}

// CommitOperations atomically commits a batch of prepared operations to the store.
// All operations in the batch are committed or none are (all-or-nothing).
func (store *InMemoryOpStore) CommitOperations(ctx context.Context, ops []*PreparedOperation) error {
	store.lock.Lock()
	defer store.lock.Unlock()

	// Verify all heads upfront before making any modifications
	// (a db implementation can do this in the main loop and roll back the tx on mismatch)
	for _, prepOp := range ops {
		currentHead := store.head[prepOp.DID]
		if currentHead != prepOp.PrevHead {
			return fmt.Errorf("head CID mismatch for DID %s", prepOp.DID)
		}
	}

	// Now apply all modifications
	for _, prepOp := range ops {
		// Handle nullifications
		for _, nullifiedCid := range prepOp.NullifiedOps {
			status := store.opStatus[nullifiedCid]
			if status == nil {
				// This implies an implementation bug, should be unreachable
				return fmt.Errorf("operation not found during nullification: %s", nullifiedCid)
			}
			if status.DID != prepOp.DID {
				// This implies an implementation bug, should be unreachable
				return fmt.Errorf("operation belongs to different DID during nullification")
			}
			status.Nullified = true
		}

		// Update previous operation's metadata if not a genesis op
		if prepOp.PrevHead != "" {
			prevCidStr := prepOp.Op.PrevCIDStr()
			prevStatus := store.opStatus[prevCidStr]
			if prevStatus == nil {
				// This implies an implementation bug, should be unreachable
				return fmt.Errorf("previous operation not found: %s", prevCidStr)
			}

			// Trim allowed keys and set last child
			prevStatus.AllowedKeys = prevStatus.AllowedKeys[:prepOp.KeyIndex]
			prevStatus.LastChild = prepOp.OpCid
		}

		// Store the operation
		store.operations[prepOp.OpCid] = prepOp.Op

		// Create and store the OpStatus for the new operation
		store.opStatus[prepOp.OpCid] = &OpStatus{
			DID:         prepOp.DID,
			CreatedAt:   prepOp.CreatedAt,
			Nullified:   false,
			LastChild:   "",
			AllowedKeys: prepOp.Op.EquivalentRotationKeys(),
		}

		// Update head
		store.head[prepOp.DID] = prepOp.OpCid
	}

	return nil
}

// getValidationContext retrieves the initial information required to validate a signature for a particular operation.
// `cidStr` corresponds to the `prev` field of the operation you're trying to validate.
// For genesis ops (i.e. prev==nil), pass cidStr=="".
//
// Returns the current "head" CID of the passed DID and the OpStatus for the previous operation.
// Any subsequent calls to CommitValidatedOperations must pass the corresponding head, OpStatus values.
func getValidationContext(ctx context.Context, store OpStore, did string, cidStr string) (string, *OpStatus, error) {
	head, err := store.GetHead(ctx, did)
	if err != nil {
		return "", nil, err
	}

	if head == "" {
		if cidStr != "" {
			return "", nil, fmt.Errorf("DID not found")
		}
		return "", nil, nil // Not an error condition! just means DID is not created yet
	}

	if cidStr == "" {
		return "", nil, fmt.Errorf("expected genesis op but DID already exists")
	}

	status, err := store.GetMetadata(ctx, did, cidStr)
	if err != nil {
		return "", nil, err
	}

	return head, status, nil
}

// VerifyOperation validates and prepares a single operation for commit.
// It verifies the signature, validates timestamp consistency, and computes the nullification list.
// Returns a PreparedOperation ready to be committed to the store.
func VerifyOperation(ctx context.Context, store OpStore, did string, op Operation, createdAt time.Time) (*PreparedOperation, error) {
	head, prevStatus, err := getValidationContext(ctx, store, did, op.PrevCIDStr())
	if err != nil {
		return nil, err
	}

	// Determine allowed keys for signature verification
	var allowedKeys []string
	if op.IsGenesis() {
		calcDid, err := op.DID()
		if err != nil {
			return nil, err
		}
		if calcDid != did {
			return nil, fmt.Errorf("genesis DID does not match")
		}
		allowedKeys = op.EquivalentRotationKeys()
	} else {
		if prevStatus == nil {
			return nil, fmt.Errorf("prevStatus required for non-genesis operation")
		}
		allowedKeys = prevStatus.AllowedKeys
	}

	// Verify signature
	keyIdx, err := VerifySignatureAny(op, allowedKeys)
	if err != nil {
		return nil, err
	}

	// Create the prepared operation
	prepOp := PreparedOperation{
		DID:       did,
		PrevHead:  head,
		KeyIndex:  keyIdx,
		CreatedAt: createdAt,
		Op:        op,
		OpCid:     op.CID().String(),
	}

	// Genesis operations don't have nullifications or timestamp constraints
	if head == "" {
		prepOp.NullifiedOps = nil
		return &prepOp, nil
	}

	if prevStatus.Nullified {
		return nil, fmt.Errorf("prev CID is nullified")
	}

	if prevStatus.LastChild == "" {
		// Regular update (not a nullification)
		// Validate timestamp order
		if createdAt.Sub(prevStatus.CreatedAt) <= 0 {
			return nil, fmt.Errorf("invalid operation timestamp order")
		}
		prepOp.NullifiedOps = nil
	} else {
		// This is a nullification - validate timestamp against head
		headStatus, err := store.GetMetadata(ctx, did, head)
		if err != nil {
			return nil, err
		}
		if createdAt.Sub(headStatus.CreatedAt) <= 0 {
			return nil, fmt.Errorf("invalid operation timestamp order")
		}

		// Validate 72h constraint and build nullification list
		nullifiedOps := []string{}
		currentCid := prevStatus.LastChild
		isFirstIteration := true

		for currentCid != "" {
			nullifiedOps = append(nullifiedOps, currentCid)
			status, err := store.GetMetadata(ctx, did, currentCid)
			if err != nil {
				return nil, err
			}

			// Check 72h constraint for the first (oldest) nullified operation
			if isFirstIteration {
				if createdAt.Sub(status.CreatedAt) > 72*time.Hour {
					return nil, fmt.Errorf("cannot nullify op after 72h (%s - %s = %s)",
						createdAt, status.CreatedAt, createdAt.Sub(status.CreatedAt))
				}
				isFirstIteration = false
			}

			currentCid = status.LastChild
		}

		prepOp.NullifiedOps = nullifiedOps
	}

	return &prepOp, nil
}
