package didplc

import (
	"fmt"
	"sync"

	"github.com/bluesky-social/indigo/atproto/crypto"
)

type OpStatus struct {
	CreatedAt   string // the only immutable field here
	Nullified   bool
	LastChild   string // CID
	AllowedKeys []string
}

// Note: LogValidationContext is designed such that it could later be turned into an interface,
// optionally backed by a db rather than in-memory
// Note: ops are globally unique by CID
type LogValidationContext struct {
	head     map[string]string    // DID -> CID, tracks most recent valid op for a particular DID
	opStatus map[string]*OpStatus // CID -> OpStatus
	lock     sync.RWMutex
}

func (c *LogValidationContext) GetValidationContext(did string, prev string) (string, *OpStatus, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	head, exists := c.head[did]
	if !exists {
		if prev != "" {
			return "", nil, fmt.Errorf("DID not found")
		}
		return head, nil, nil // Not an error condition! just means DID is not created yet
	}
	status := c.opStatus[prev]
	if status == nil {
		return "", nil, fmt.Errorf("prev CID not found")
	}

	// make a deep copy of the status struct so that concurrent mutations are safe
	allowedKeysCopy := make([]string, len(status.AllowedKeys))
	copy(allowedKeysCopy, status.AllowedKeys)
	statusCopy := *status
	statusCopy.AllowedKeys = allowedKeysCopy

	return head, &statusCopy, nil
}

func (c *LogValidationContext) CommitValidOperation(did string, head string, prevStatus *OpStatus, op Operation, createdAt string, keyIndex uint) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	if head != c.head[did] {
		return fmt.Errorf("head CID mismatch")
	}
	if head == "" {
		if !op.IsGenesis() {
			return fmt.Errorf("expected genesis op")
		}
	}
	this_cid := op.CID().String()
	if !op.IsGenesis() {
		if prevStatus == nil {
			return fmt.Errorf("invalid prevStatus")
		}
		if prevStatus.Nullified {
			return fmt.Errorf("prev CID is nullified")
		}
		c.markNullifiedOp(prevStatus.LastChild) // recursive, a nop if LastChild is ""
		prevStatus.AllowedKeys = prevStatus.AllowedKeys[:keyIndex]
		prevStatus.LastChild = this_cid
		c.opStatus[op.PrevCIDStr()] = prevStatus // prevStatus was a copy so we need to write it back
	}
	c.head[did] = this_cid
	c.opStatus[this_cid] = &OpStatus{
		CreatedAt:   createdAt,
		Nullified:   false,
		LastChild:   "",
		AllowedKeys: op.EquivalentRotationKeys(),
	}
	return nil
}

func (c *LogValidationContext) markNullifiedOp(cid string) {
	if cid == "" {
		return
	}
	op := c.opStatus[cid]
	if op == nil {
		panic("cid lookup failed during op nullification")
	}
	if op.Nullified {
		return
	}
	op.Nullified = true
	c.markNullifiedOp(op.LastChild)
}

type LogEntry struct {
	DID       string `json:"did"`
	Operation OpEnum `json:"operation"`
	CID       string `json:"cid"`
	Nullified bool   `json:"nullified"`
	CreatedAt string `json:"createdAt"`
}

// Checks self-consistency of this log entry in isolation. Does not access other context or log entries.
func (le *LogEntry) Validate() error {

	if le.Operation.Regular != nil {
		if le.CID != le.Operation.Regular.CID().String() {
			return fmt.Errorf("log entry CID didn't match computed operation CID")
		}
		// NOTE: for non-genesis ops, the rotation key may have bene in a previous op
		if le.Operation.Regular.IsGenesis() {
			did, err := le.Operation.Regular.DID()
			if err != nil {
				return err
			}
			if le.DID != did {
				return fmt.Errorf("log entry DID didn't match computed genesis operation DID")
			}
			if err := VerifySignatureAny(le.Operation.Regular, le.Operation.Regular.RotationKeys); err != nil {
				return fmt.Errorf("failed to validate op genesis signature: %v", err)
			}
		}
	} else if le.Operation.Legacy != nil {
		if le.CID != le.Operation.Legacy.CID().String() {
			return fmt.Errorf("log entry CID didn't match computed operation CID")
		}
		// NOTE: for non-genesis ops, the rotation key may have bene in a previous op
		if le.Operation.Legacy.IsGenesis() {
			did, err := le.Operation.Legacy.DID()
			if err != nil {
				return err
			}
			if le.DID != did {
				return fmt.Errorf("log entry DID didn't match computed genesis operation DID")
			}
			// TODO: try both signing and recovery key?
			pub, err := crypto.ParsePublicDIDKey(le.Operation.Legacy.SigningKey)
			if err != nil {
				return fmt.Errorf("could not parse recovery key: %v", err)
			}
			if err := le.Operation.Legacy.VerifySignature(pub); err != nil {
				return fmt.Errorf("failed to validate legacy op genesis signature: %v", err)
			}
		}
	} else if le.Operation.Tombstone != nil {
		if le.CID != le.Operation.Tombstone.CID().String() {
			return fmt.Errorf("log entry CID didn't match computed operation CID")
		}
		// NOTE: for tombstones, the rotation key is always in a previous op
	} else {
		return fmt.Errorf("expected tombstone, legacy, or regular PLC operation")
	}

	return nil
}

// checks and ordered list of operations for a single DID.
//
// can be a full audit log (with nullified entries), or a simple log (only "active" entries)
func VerifyOpLog(entries []LogEntry) error {
	if len(entries) == 0 {
		return fmt.Errorf("can't verify empty operation log")
	}

	did := entries[0].DID
	vctx := LogValidationContext{
		head:     make(map[string]string),
		opStatus: make(map[string]*OpStatus),
	}

	for _, oe := range entries {
		if oe.DID != did {
			return fmt.Errorf("inconsistent DID")
		}
		if err := oe.Validate(); err != nil {
			return err
		}
		op := oe.Operation.AsOperation()
		if op.CID().String() != oe.CID {
			return fmt.Errorf("inconsistent CID")
		}

		//fmt.Println(oe.DID, oe.CID) // XXX: debugging

		head, prevStatus, err := vctx.GetValidationContext(did, op.PrevCIDStr())
		if err != nil {
			return err
		}

		// TODO: check timestamp parses

		if op.IsGenesis() {
			calc_did, err := op.DID()
			if err != nil {
				return err
			}
			if calc_did != did {
				return fmt.Errorf("genesis DID does not match")
			}

			err = VerifySignatureAny(op, op.EquivalentRotationKeys())
			if err != nil {
				return err
			}
			vctx.CommitValidOperation(did, head, prevStatus, op, oe.CreatedAt, 0)
		} else { // not-genesis
			// TODO: timestamp difference validation
			validSig := false
			for keyIdx, pubkey := range prevStatus.AllowedKeys {
				err := VerifySignatureAny(op, []string{pubkey})
				if err != nil {
					continue
				}
				validSig = true
				vctx.CommitValidOperation(did, head, prevStatus, op, oe.CreatedAt, uint(keyIdx))
				break
			}
			if !validSig {
				return fmt.Errorf("invalid signature")
			}
		}
	}

	// check consistency of `nullified` fields
	for idx, oe := range entries {
		if idx == 0 {
			if oe.Nullified {
				return fmt.Errorf("genesis op cannot be nullified")
			}
		} else {
			_, status, err := vctx.GetValidationContext(did, oe.CID)
			if err != nil {
				return err
			}
			if status.Nullified != oe.Nullified {
				return fmt.Errorf("inconsistent nullification status for %s %s", did, oe.CID)
			}
		}
	}

	return nil
}
