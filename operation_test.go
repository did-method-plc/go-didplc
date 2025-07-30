package didplc

import (
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/bluesky-social/indigo/atproto/crypto"
	"github.com/bluesky-social/indigo/atproto/syntax"

	"github.com/stretchr/testify/assert"
)

var VALID_LOG_PATHS = [...]string{
	"testdata/log_bskyapp.json",
	"testdata/log_legacy_dholms.json",
	"testdata/log_bnewbold_robocracy.json",
	"testdata/log_empty_rotation_keys.json",
	"testdata/log_duplicate_rotation_keys.json", // XXX: invalid according to spec, valid according to TS reference impl
	"testdata/log_nullification.json",
	"testdata/log_nullification_nontrivial.json",
	"testdata/log_nullification_at_exactly_72h.json",
	"testdata/log_nullified_tombstone.json",
	"testdata/log_tombstone.json",
}

var INVALID_LOG_PATHS = [...]string{
	"testdata/log_invalid_sig_b64_padding_chars.json",
	"testdata/log_invalid_sig_b64_padding_bits.json",
	"testdata/log_invalid_sig_b64_newline.json",
	"testdata/log_invalid_sig_der.json",
	"testdata/log_invalid_sig_p256_high_s.json",
	"testdata/log_invalid_sig_k256_high_s.json",
	"testdata/log_invalid_nullification_reused_key.json",
	"testdata/log_invalid_nullification_too_slow.json",
	"testdata/log_invalid_update_nullified.json",
	"testdata/log_invalid_update_tombstoned.json",
}

func loadTestLogEntries(t *testing.T, p string) []LogEntry {
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	fileBytes, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}

	var entries []LogEntry
	if err := json.Unmarshal(fileBytes, &entries); err != nil {
		t.Fatal(err)
	}

	return entries
}

func TestLogEntryValidate(t *testing.T) {
	assert := assert.New(t)

	for _, p := range VALID_LOG_PATHS {
		entries := loadTestLogEntries(t, p)
		for _, le := range entries {
			assert.NoError(le.Validate(), p)
		}
	}
}

// similar to the above test, but audits the log as a whole rather than inspecting individual ops
func TestAuditLogValidate(t *testing.T) {
	assert := assert.New(t)

	for _, p := range VALID_LOG_PATHS {
		entries := loadTestLogEntries(t, p)
		assert.NoError(VerifyOpLog(entries), p)
	}
}

func TestLogEntryInvalid(t *testing.T) {
	assert := assert.New(t)

	for _, p := range INVALID_LOG_PATHS {
		if strings.Contains(p, "nullif") {
			continue // nullification-related negative tests cannot apply to individual ops
		}
		if strings.Contains(p, "tombstone") {
			continue // likewise for tombstoning-related tests
		}
		entries := loadTestLogEntries(t, p)
		for _, le := range entries {
			assert.Error(le.Validate(), p)
		}
	}
}

func TestAuditLogInvalidSigEncoding(t *testing.T) {
	assert := assert.New(t)

	entries := loadTestLogEntries(t, "testdata/log_invalid_sig_b64_padding_chars.json")
	assert.ErrorContains(VerifyOpLog(entries), "illegal base64")

	entries = loadTestLogEntries(t, "testdata/log_invalid_sig_b64_padding_bits.json")
	assert.ErrorContains(VerifyOpLog(entries), "illegal base64")

	entries = loadTestLogEntries(t, "testdata/log_invalid_sig_b64_newline.json")
	assert.ErrorContains(VerifyOpLog(entries), "CRLF")

	entries = loadTestLogEntries(t, "testdata/log_invalid_sig_der.json")
	assert.EqualError(VerifyOpLog(entries), "crytographic signature invalid") // Note: there is no reliable way to detect DER-encoded signatures syntactically, so a generic invalid signature error is expected

	entries = loadTestLogEntries(t, "testdata/log_invalid_sig_p256_high_s.json")
	assert.EqualError(VerifyOpLog(entries), "crytographic signature invalid")

	entries = loadTestLogEntries(t, "testdata/log_invalid_sig_k256_high_s.json")
	assert.EqualError(VerifyOpLog(entries), "crytographic signature invalid")

}

func TestAuditLogInvalidNullification(t *testing.T) {
	assert := assert.New(t)

	entries := loadTestLogEntries(t, "testdata/log_invalid_nullification_reused_key.json")
	assert.EqualError(VerifyOpLog(entries), "crytographic signature invalid") // TODO: This is the expected error message for the current impl logic. This could be improved.

	entries = loadTestLogEntries(t, "testdata/log_invalid_nullification_too_slow.json")
	assert.ErrorContains(VerifyOpLog(entries), "cannot nullify op after 72h")

	entries = loadTestLogEntries(t, "testdata/log_invalid_update_nullified.json")
	assert.EqualError(VerifyOpLog(entries), "prev CID is nullified")
}

func TestAuditLogInvalidTombstoneUpdate(t *testing.T) {
	assert := assert.New(t)

	entries := loadTestLogEntries(t, "testdata/log_invalid_update_tombstoned.json")
	assert.EqualError(VerifyOpLog(entries), "no keys to verify against") // TODO: This is the expected error message for the current impl logic. This could be improved.
}

func TestCreatePLC(t *testing.T) {
	assert := assert.New(t)

	priv, err := crypto.GeneratePrivateKeyP256()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	pubDIDKey := pub.DIDKey()
	handleURI := "at://handle.example.com"
	endpoint := "https://pds.example.com"
	op := RegularOp{
		Type:         "plc_operation",
		RotationKeys: []string{pubDIDKey},
		VerificationMethods: map[string]string{
			"atproto": pubDIDKey,
		},
		AlsoKnownAs: []string{handleURI},
		Services: map[string]OpService{
			"atproto_pds": OpService{
				Type:     "AtprotoPersonalDataServer",
				Endpoint: endpoint,
			},
		},
		Prev: nil,
		Sig:  nil,
	}
	assert.NoError(op.Sign(priv))
	assert.NoError(op.VerifySignature(pub))
	did, err := op.DID()
	if err != nil {
		t.Fatal(err)
	}
	_, err = syntax.ParseDID(did)
	assert.NoError(err)

	le := LogEntry{
		DID:       did,
		Operation: OpEnum{Regular: &op},
		CID:       op.CID().String(),
		Nullified: false,
		CreatedAt: syntax.DatetimeNow().String(),
	}
	assert.NoError(le.Validate())

	_, err = op.Doc(did)
	assert.NoError(err)
}
