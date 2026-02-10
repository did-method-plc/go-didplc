package replica

import (
	"sync"

	"github.com/emirpasic/gods/sets/hashset"
	"github.com/emirpasic/gods/sets/treeset"
	"github.com/emirpasic/gods/utils"
)

// The ingestor validates operations concurrently and commits them in batches.
//
// It is important that:
//
//   - All operations for a particular DID are processed in upstream-seq order.
//
//   - No two operations for the same DID are "in flight" concurrently,
//     where "in flight" means they're present somewhere in the validation->commit pipeline.
//
//   - When the replica process is shut down and restarted, it should resume ingest from a cursor
//     value that is definitely lower than any as-yet-uncommitted operations, guaranteeing that each operation
//     is processed at-least-once. This means that after a restart, some operations may be processed for
//     a second time - this is ok because they will not pass validation the second time, and will be ignored.
//
// The InFlight struct is central to enforcing the above constraints.
//
// [InFlight.AddInFlight] should be called before inserting an operation into the to-be-validated queue.
// If [InFlight.AddInFlight] fails (returns false, indicating that there was an already an op in-flight for the same DID),
// it is expected that the caller will retry until it succeeds (eventually, the work queue will drain).
//
// [InFlight.RemoveInFlight] should be called *after* an operation has been processed (whether it was rejected as an invalid operation, or successfully committed to the db)
type InFlight struct {
	resumeCursor int64 // all seqs <= this value have already been processed and committed to db (or rejected as invalid)
	dids         *hashset.Set
	seqs         *treeset.Set // treeset means we can find the minimum efficiently
	removed      *treeset.Set // seqs that have been removed but are ahead of the resumeCursor
	lock         sync.RWMutex
}

func NewInFlight(resumeCursor int64) *InFlight {
	return &InFlight{
		resumeCursor: resumeCursor,
		dids:         hashset.New(),
		seqs:         treeset.NewWith(utils.Int64Comparator),
		removed:      treeset.NewWith(utils.Int64Comparator),
	}
}

func (infl *InFlight) GetResumeCursor() int64 {
	infl.lock.RLock()
	defer infl.lock.RUnlock()
	return infl.resumeCursor
}

// returns true on success, does nothing and returns false if the DID was already in-flight
func (infl *InFlight) AddInFlight(did string, seq int64) bool {
	infl.lock.Lock()
	defer infl.lock.Unlock()

	if infl.dids.Contains(did) {
		return false
	}

	infl.dids.Add(did)
	infl.seqs.Add(seq)

	return true
}

// always succeeds, and updates resumeCursor if appropriate
func (infl *InFlight) RemoveInFlight(did string, seq int64) {
	infl.lock.Lock()
	defer infl.lock.Unlock()

	// just for extra safety, do nothing if it's already been removed
	if !infl.dids.Contains(did) {
		// if you reached here you're using the API wrong
		return
	}

	infl.dids.Remove(did)
	infl.seqs.Remove(seq)
	infl.removed.Add(seq)

	// drain: advance cursor past completed seqs below the lowest inflight
	for {
		it := infl.removed.Iterator()
		if !it.First() {
			break
		}
		minRemoved := it.Value().(int64)

		inflIt := infl.seqs.Iterator()
		if inflIt.First() {
			minInflight := inflIt.Value().(int64)
			if minRemoved >= minInflight {
				break
			}
		}

		// minRemoved is below all inflight items (or inflight is empty), advance cursor
		infl.resumeCursor = minRemoved
		infl.removed.Remove(minRemoved)
	}
}
