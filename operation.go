package didplc

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/bluesky-social/indigo/atproto/atcrypto"

	"github.com/ipfs/go-cid"
	cbor "github.com/ipfs/go-ipld-cbor"
)

// Interface implemented by all operation types.
type Operation interface {
	// CID of the full (signed) operation
	CID() cid.Cid
	// serializes a copy of the op as CBOR, with the `sig` field omitted
	UnsignedCBORBytes() []byte
	// serializes a copy of the op as CBOR, with the `sig` field included
	SignedCBORBytes() []byte
	// whether this operation is a genesis (creation) op
	IsGenesis() bool
	// whether this operation has a signature or is unsigned
	IsSigned() bool
	// returns the DID for a genesis op (errors if this op is not a genesis op, or is not signed)
	DID() (string, error)
	// signs the object in-place
	Sign(priv atcrypto.PrivateKey) error
	// verifiy signature. returns atcrypto.ErrInvalidSignature if appropriate
	VerifySignature(pub atcrypto.PublicKey) error
	// returns a DID doc
	Doc(did string) (Doc, error)
	// logical equivalent of RotationKeys for any op type
	// ({RecoveryKey, SigningKey} for legacy genesis, empty slice for Tombstone)
	EquivalentRotationKeys() []string
	// CID of the previous operation ("" for genesis ops)
	PrevCIDStr() string
}

type OpService struct {
	Type     string `json:"type" cborgen:"type"`
	Endpoint string `json:"endpoint" cborgen:"endpoint"`
}

// Represents normal operation under the current version of the PLC specification.
type RegularOp struct {
	// Type is "plc_operation"
	Type                string               `json:"type" cborgen:"type"`
	RotationKeys        []string             `json:"rotationKeys" cborgen:"rotationKeys"`
	VerificationMethods map[string]string    `json:"verificationMethods" cborgen:"verificationMethods"`
	AlsoKnownAs         []string             `json:"alsoKnownAs" cborgen:"alsoKnownAs"`
	Services            map[string]OpService `json:"services" cborgen:"services"`
	Prev                *string              `json:"prev" cborgen:"prev"`
	Sig                 *string              `json:"sig,omitempty" cborgen:"sig,omitempty" refmt:"sig,omitempty"`
}

// Represents a "tombstone" operation, which indicates that the DID has been deleted.
type TombstoneOp struct {
	// Type is "plc_tombstone"
	Type string  `json:"type" cborgen:"type"`
	Prev string  `json:"prev" cborgen:"prev"`
	Sig  *string `json:"sig,omitempty" cborgen:"sig,omitempty" refmt:"sig,omitempty"`
}

// Represents a valid legacy operation.
//
// New operations should not be created in this legacy format, but existing operations in the directory are still supported by the specification.
type LegacyOp struct {
	// Type is "create"
	Type        string  `json:"type" cborgen:"type"`
	SigningKey  string  `json:"signingKey" cborgen:"signingKey"`
	RecoveryKey string  `json:"recoveryKey" cborgen:"recoveryKey"`
	Handle      string  `json:"handle" cborgen:"handle"`
	Service     string  `json:"service" cborgen:"service"`
	Prev        *string `json:"prev" cborgen:"prev"`
	Sig         *string `json:"sig,omitempty" cborgen:"sig,omitempty" refmt:"sig,omitempty"`
}

var _ Operation = (*RegularOp)(nil)
var _ Operation = (*TombstoneOp)(nil)
var _ Operation = (*LegacyOp)(nil)

// A concrete type representing a single operation, which is one of [Op], [TombstoneOp], or [LegacyOp].
type OpEnum struct {
	Regular   *RegularOp
	Tombstone *TombstoneOp
	Legacy    *LegacyOp
}

var ErrNotGenesisOp = errors.New("not a genesis PLC operation")
var ErrNotSignedOp = errors.New("not a signed PLC operation")

func init() {
	cbor.RegisterCborType(OpService{})
	cbor.RegisterCborType(RegularOp{})
	cbor.RegisterCborType(TombstoneOp{})
	cbor.RegisterCborType(LegacyOp{})
}

func computeCID(b []byte) cid.Cid {
	cidBuilder := cid.V1Builder{Codec: 0x71, MhType: 0x12, MhLength: 0}
	c, err := cidBuilder.Sum(b)
	if err != nil {
		return cid.Undef
	}
	return c
}

func (op *RegularOp) CID() cid.Cid {
	return computeCID(op.SignedCBORBytes())
}

func (op *RegularOp) UnsignedCBORBytes() []byte {
	unsigned := RegularOp{
		Type:                op.Type,
		RotationKeys:        op.RotationKeys,
		VerificationMethods: op.VerificationMethods,
		AlsoKnownAs:         op.AlsoKnownAs,
		Services:            op.Services,
		Prev:                op.Prev,
		Sig:                 nil,
	}

	out, err := cbor.DumpObject(unsigned)
	if err != nil {
		return nil
	}
	return out
}

func (op *RegularOp) SignedCBORBytes() []byte {
	out, err := cbor.DumpObject(op)
	if err != nil {
		return nil
	}
	return out
}

func (op *RegularOp) IsGenesis() bool {
	return op.Prev == nil
}

func (op *RegularOp) IsSigned() bool {
	return op.Sig != nil && *op.Sig != ""
}

func (op *RegularOp) DID() (string, error) {
	if !op.IsGenesis() {
		return "", ErrNotGenesisOp
	}
	if !op.IsSigned() {
		return "", ErrNotSignedOp
	}
	hash := sha256.Sum256(op.SignedCBORBytes())
	suffix := base32.StdEncoding.EncodeToString(hash[:])[:24]
	return "did:plc:" + strings.ToLower(suffix), nil
}

func signOp(op Operation, priv atcrypto.PrivateKey) (string, error) {
	b := op.UnsignedCBORBytes()
	sig, err := priv.HashAndSign(b)
	if err != nil {
		return "", err
	}
	b64 := base64.RawURLEncoding.EncodeToString(sig)
	return b64, nil
}

func (op *RegularOp) Sign(priv atcrypto.PrivateKey) error {
	sig, err := signOp(op, priv)
	if err != nil {
		return err
	}
	op.Sig = &sig
	return nil
}

func verifySigOp(op Operation, pub atcrypto.PublicKey, sig *string) error {
	if sig == nil || *sig == "" {
		return fmt.Errorf("can't verify empty signature")
	}

	// this check is required because .Strict() alone is not strict enough.
	// see https://pkg.go.dev/encoding/base64#Encoding.Strict
	if strings.Contains(*sig, "\r") || strings.Contains(*sig, "\n") {
		return fmt.Errorf("invalid signature encoding (CRLF)")
	}

	b := op.UnsignedCBORBytes()
	sigBytes, err := base64.RawURLEncoding.Strict().DecodeString(*sig)
	if err != nil {
		return err
	}
	return pub.HashAndVerify(b, sigBytes)
}

// parsing errors are not ignored (will be returned immediately if found)
// on success, the index of the first key that was able to validate the signature is returned
func VerifySignatureAny(op Operation, didKeys []string) (int, error) {
	if len(didKeys) == 0 {
		return -1, fmt.Errorf("no keys to verify against")
	}
	for idx, dk := range didKeys {
		pub, err := atcrypto.ParsePublicDIDKey(dk)
		if err != nil {
			return -1, err
		}
		err = op.VerifySignature(pub)
		if nil == err {
			return idx, nil
		}
		if err != atcrypto.ErrInvalidSignature {
			return -1, err
		}
	}
	return -1, atcrypto.ErrInvalidSignature
}

func (op *RegularOp) VerifySignature(pub atcrypto.PublicKey) error {
	return verifySigOp(op, pub, op.Sig)
}

func (op *RegularOp) Doc(did string) (Doc, error) {
	svc := []DocService{}
	for key, s := range op.Services {
		svc = append(svc, DocService{
			ID:              did + "#" + key,
			Type:            s.Type,
			ServiceEndpoint: s.Endpoint,
		})
	}
	vm := []DocVerificationMethod{}
	for name, didKey := range op.VerificationMethods {
		pub, err := atcrypto.ParsePublicDIDKey(didKey)
		if err != nil {
			return Doc{}, err
		}
		vm = append(vm, DocVerificationMethod{
			ID:                 did + "#" + name,
			Type:               "Multikey",
			Controller:         did,
			PublicKeyMultibase: pub.Multibase(),
		})
	}
	doc := Doc{
		ID:                 did,
		AlsoKnownAs:        op.AlsoKnownAs,
		VerificationMethod: vm,
		Service:            svc,
	}
	return doc, nil
}

func (op *RegularOp) EquivalentRotationKeys() []string {
	return op.RotationKeys
}

func (op *RegularOp) PrevCIDStr() string {
	if op.Prev == nil {
		return ""
	}
	return *op.Prev
}

func (op *LegacyOp) CID() cid.Cid {
	return computeCID(op.SignedCBORBytes())
}

func (op *LegacyOp) UnsignedCBORBytes() []byte {
	unsigned := LegacyOp{
		Type:        op.Type,
		SigningKey:  op.SigningKey,
		RecoveryKey: op.RecoveryKey,
		Handle:      op.Handle,
		Service:     op.Service,
		Prev:        op.Prev,
		Sig:         nil,
	}
	out, err := cbor.DumpObject(unsigned)
	if err != nil {
		return nil
	}
	return out
}

func (op *LegacyOp) SignedCBORBytes() []byte {
	out, err := cbor.DumpObject(op)
	if err != nil {
		return nil
	}
	return out
}

func (op *LegacyOp) IsGenesis() bool {
	return op.Prev == nil
}

func (op *LegacyOp) IsSigned() bool {
	return op.Sig != nil && *op.Sig != ""
}

func (op *LegacyOp) DID() (string, error) {
	if !op.IsGenesis() {
		return "", ErrNotGenesisOp
	}
	if !op.IsSigned() {
		return "", ErrNotSignedOp
	}
	hash := sha256.Sum256(op.SignedCBORBytes())
	suffix := base32.StdEncoding.EncodeToString(hash[:])[:24]
	return "did:plc:" + strings.ToLower(suffix), nil
}

func (op *LegacyOp) Sign(priv atcrypto.PrivateKey) error {
	sig, err := signOp(op, priv)
	if err != nil {
		return err
	}
	op.Sig = &sig
	return nil
}

func (op *LegacyOp) VerifySignature(pub atcrypto.PublicKey) error {
	return verifySigOp(op, pub, op.Sig)
}

func (op *LegacyOp) Doc(did string) (Doc, error) {
	// NOTE: could re-implement this by calling op.RegularOp().Doc()
	svc := []DocService{
		DocService{
			ID:              did + "#atproto_pds",
			Type:            "AtprotoPersonalDataServer",
			ServiceEndpoint: op.Service,
		},
	}
	vm := []DocVerificationMethod{
		DocVerificationMethod{
			ID:                 did + "#atproto",
			Type:               "Multikey",
			Controller:         did,
			PublicKeyMultibase: strings.TrimPrefix(op.SigningKey, "did:key:"),
		},
	}
	doc := Doc{
		ID:                 did,
		AlsoKnownAs:        []string{"at://" + op.Handle},
		VerificationMethod: vm,
		Service:            svc,
	}
	return doc, nil
}

// converts a legacy "create" op to an (unsigned) "plc_operation"
func (op *LegacyOp) RegularOp() RegularOp {
	return RegularOp{
		RotationKeys: op.EquivalentRotationKeys(),
		VerificationMethods: map[string]string{
			"atproto": op.SigningKey,
		},
		AlsoKnownAs: []string{"at://" + op.Handle},
		Services: map[string]OpService{
			"atproto_pds": OpService{
				Type:     "AtprotoPersonalDataServer",
				Endpoint: op.Service,
			},
		},
		Prev: nil, // always a create
		Sig:  nil, // don't have private key
	}
}

func (op *LegacyOp) EquivalentRotationKeys() []string {
	return []string{op.RecoveryKey, op.SigningKey}
}

func (op *LegacyOp) PrevCIDStr() string {
	if op.Prev == nil {
		return ""
	}
	return *op.Prev
}

func (op *TombstoneOp) CID() cid.Cid {
	return computeCID(op.SignedCBORBytes())
}

func (op *TombstoneOp) UnsignedCBORBytes() []byte {
	unsigned := TombstoneOp{
		Type: op.Type,
		Prev: op.Prev,
		Sig:  nil,
	}
	out, err := cbor.DumpObject(unsigned)
	if err != nil {
		return nil
	}
	return out
}

func (op *TombstoneOp) SignedCBORBytes() []byte {
	out, err := cbor.DumpObject(op)
	if err != nil {
		return nil
	}
	return out
}

func (op *TombstoneOp) IsGenesis() bool {
	return false
}

func (op *TombstoneOp) IsSigned() bool {
	return op.Sig != nil && *op.Sig != ""
}

func (op *TombstoneOp) DID() (string, error) {
	return "", ErrNotGenesisOp
}

func (op *TombstoneOp) Sign(priv atcrypto.PrivateKey) error {
	sig, err := signOp(op, priv)
	if err != nil {
		return err
	}
	op.Sig = &sig
	return nil
}

func (op *TombstoneOp) VerifySignature(pub atcrypto.PublicKey) error {
	return verifySigOp(op, pub, op.Sig)
}

func (op *TombstoneOp) Doc(did string) (Doc, error) {
	return Doc{}, fmt.Errorf("tombstones do not have a DID document representation")
}

func (op *TombstoneOp) EquivalentRotationKeys() []string {
	return []string{}
}

func (op *TombstoneOp) PrevCIDStr() string {
	return op.Prev
}

func (o *OpEnum) MarshalJSON() ([]byte, error) {
	if o.Regular != nil {
		return json.Marshal(o.Regular)
	} else if o.Legacy != nil {
		return json.Marshal(o.Legacy)
	} else if o.Tombstone != nil {
		return json.Marshal(o.Tombstone)
	}
	return nil, fmt.Errorf("can't marshal empty OpEnum")
}

// like json.Unmarshal, but rejecting objects with unknown fields
// TODO: also require case sensitivity (requires migrating to json/v2)q
func strictUnmarshal(b []byte, v interface{}) error {
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	return decoder.Decode(v)
}

func (o *OpEnum) UnmarshalJSON(b []byte) error {
	var typeMap map[string]interface{}
	err := json.Unmarshal(b, &typeMap)
	if err != nil {
		return err
	}
	typ, ok := typeMap["type"]
	if !ok {
		return fmt.Errorf("did not find expected operation 'type' field")
	}

	switch typ {
	case "plc_operation":
		o.Regular = &RegularOp{}
		return strictUnmarshal(b, o.Regular)
	case "create":
		o.Legacy = &LegacyOp{}
		return strictUnmarshal(b, o.Legacy)
	case "plc_tombstone":
		o.Tombstone = &TombstoneOp{}
		return strictUnmarshal(b, o.Tombstone)
	default:
		return fmt.Errorf("unexpected operation type: %s", typ)
	}
}

// returns a new signed PLC operation using the provided atproto-specific metdata
func NewAtproto(priv atcrypto.PrivateKey, handle string, pdsEndpoint string, rotationKeys []string) (RegularOp, error) {

	pub, err := priv.PublicKey()
	if err != nil {
		return RegularOp{}, err
	}
	if len(rotationKeys) == 0 {
		return RegularOp{}, fmt.Errorf("at least one rotation key is required")
	}
	handleURI := "at://" + handle
	op := RegularOp{
		RotationKeys: rotationKeys,
		VerificationMethods: map[string]string{
			"atproto": pub.DIDKey(),
		},
		AlsoKnownAs: []string{handleURI},
		Services: map[string]OpService{
			"atproto_pds": OpService{
				Type:     "AtprotoPersonalDataServer",
				Endpoint: pdsEndpoint,
			},
		},
		Prev: nil,
		Sig:  nil,
	}
	if err := op.Sign(priv); err != nil {
		return RegularOp{}, err
	}
	return op, nil
}

func (oe *OpEnum) AsOperation() Operation {
	if oe.Regular != nil {
		return oe.Regular
	} else if oe.Legacy != nil {
		return oe.Legacy
	} else if oe.Tombstone != nil {
		return oe.Tombstone
	} else {
		// TODO; something more safe here?
		return nil
	}
}
