package replica

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddInFlight_Success(t *testing.T) {
	assert := assert.New(t)

	infl := NewInFlight(-1)

	added := infl.AddInFlight("did:plc:test123", 100)
	assert.True(added, "first add should succeed")
}

func TestAddInFlight_DuplicateDID(t *testing.T) {
	assert := assert.New(t)

	infl := NewInFlight(-1)

	added1 := infl.AddInFlight("did:plc:test123", 100)
	assert.True(added1, "first add should succeed")

	added2 := infl.AddInFlight("did:plc:test123", 200)
	assert.False(added2, "adding same DID twice should return false")
}

func TestAddInFlight_MultipleDIDs(t *testing.T) {
	assert := assert.New(t)

	infl := NewInFlight(-1)

	added1 := infl.AddInFlight("did:plc:test1", 100)
	assert.True(added1)

	added2 := infl.AddInFlight("did:plc:test2", 200)
	assert.True(added2)

	added3 := infl.AddInFlight("did:plc:test3", 150)
	assert.True(added3)
}

func TestRemoveInFlight_TracksResumeCursor(t *testing.T) {
	assert := assert.New(t)

	infl := NewInFlight(-1)

	infl.AddInFlight("did:plc:test1", 100)
	infl.AddInFlight("did:plc:test2", 200)
	infl.AddInFlight("did:plc:test3", 300)
	infl.AddInFlight("did:plc:test4", 400)
	infl.AddInFlight("did:plc:test5", 500)

	assert.Equal(infl.GetResumeCursor(), int64(-1))

	infl.RemoveInFlight("did:plc:test2", 200)

	assert.Equal(infl.GetResumeCursor(), int64(-1))

	infl.RemoveInFlight("did:plc:test4", 400)

	assert.Equal(infl.GetResumeCursor(), int64(-1))

	infl.RemoveInFlight("did:plc:test1", 100)

	assert.Equal(infl.GetResumeCursor(), int64(200))

	infl.RemoveInFlight("did:plc:test3", 300)

	assert.Equal(infl.GetResumeCursor(), int64(400))
}

func TestRemoveInFlight_RemoveAll(t *testing.T) {
	assert := assert.New(t)

	infl := NewInFlight(-1)

	infl.AddInFlight("did:plc:test1", 100)
	infl.AddInFlight("did:plc:test2", 200)
	infl.AddInFlight("did:plc:test3", 300)

	infl.RemoveInFlight("did:plc:test2", 200)
	infl.RemoveInFlight("did:plc:test1", 100)
	assert.Equal(int64(200), infl.GetResumeCursor())

	infl.RemoveInFlight("did:plc:test3", 300)
	assert.Equal(int64(300), infl.GetResumeCursor())
}

func TestRemoveInFlight_ReverseOrder(t *testing.T) {
	assert := assert.New(t)

	infl := NewInFlight(-1)

	infl.AddInFlight("did:plc:test1", 100)
	infl.AddInFlight("did:plc:test2", 200)
	infl.AddInFlight("did:plc:test3", 300)
	infl.AddInFlight("did:plc:test4", 400)

	infl.RemoveInFlight("did:plc:test4", 400)
	assert.Equal(int64(-1), infl.GetResumeCursor())

	infl.RemoveInFlight("did:plc:test3", 300)
	assert.Equal(int64(-1), infl.GetResumeCursor())

	infl.RemoveInFlight("did:plc:test2", 200)
	assert.Equal(int64(-1), infl.GetResumeCursor())

	infl.RemoveInFlight("did:plc:test1", 100)
	assert.Equal(int64(400), infl.GetResumeCursor())
}

func TestRemoveInFlight_DoubleRemove(t *testing.T) {
	assert := assert.New(t)

	infl := NewInFlight(-1)

	infl.AddInFlight("did:plc:test1", 100)
	infl.AddInFlight("did:plc:test2", 200)
	infl.AddInFlight("did:plc:test3", 300)

	infl.RemoveInFlight("did:plc:test1", 100)
	infl.RemoveInFlight("did:plc:test2", 200)
	assert.Equal(int64(200), infl.GetResumeCursor())

	// double remove should not regress cursor
	infl.RemoveInFlight("did:plc:test1", 100)
	assert.Equal(int64(200), infl.GetResumeCursor())
}

func TestRemoveInFlight_InterleavedAddsAndRemoves(t *testing.T) {
	assert := assert.New(t)

	infl := NewInFlight(-1)

	infl.AddInFlight("did:plc:test1", 100)
	infl.AddInFlight("did:plc:test2", 200)

	infl.RemoveInFlight("did:plc:test1", 100)
	assert.Equal(int64(100), infl.GetResumeCursor())

	infl.AddInFlight("did:plc:test3", 300)
	infl.AddInFlight("did:plc:test4", 400)

	infl.RemoveInFlight("did:plc:test4", 400)
	assert.Equal(int64(100), infl.GetResumeCursor())

	infl.RemoveInFlight("did:plc:test2", 200)
	assert.Equal(int64(200), infl.GetResumeCursor())

	infl.RemoveInFlight("did:plc:test3", 300)
	assert.Equal(int64(400), infl.GetResumeCursor())
}

func TestRemoveInFlight_AllowsReAdd(t *testing.T) {
	assert := assert.New(t)

	infl := NewInFlight(-1)

	added1 := infl.AddInFlight("did:plc:test1", 100)
	assert.True(added1)

	infl.RemoveInFlight("did:plc:test1", 100)

	added2 := infl.AddInFlight("did:plc:test1", 200)
	assert.True(added2, "should allow re-adding DID after removal")
}
