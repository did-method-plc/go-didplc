package replica

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/did-method-plc/go-didplc/didplc"
	slogGorm "github.com/orandin/slog-gorm"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// opEnumDB wraps didplc.OpEnum to provide SQL Scanner/Valuer for GORM storage.
type opEnumDB didplc.OpEnum

func (o opEnumDB) Value() (driver.Value, error) {
	return json.Marshal((*didplc.OpEnum)(&o))
}

func (o *opEnumDB) Scan(value interface{}) error {
	var bytes []byte
	switch v := value.(type) {
	case string:
		bytes = []byte(v)
	case []byte:
		bytes = v
	default:
		return fmt.Errorf("unsupported type for opEnumDB: %T", value)
	}
	return json.Unmarshal(bytes, (*didplc.OpEnum)(o))
}

// Head represents the current head CID for a DID
type Head struct {
	DID string `gorm:"column:did;primaryKey"`
	CID string `gorm:"column:cid;not null"`
}

// OperationRecord represents a stored operation with its status in the database
type OperationRecord struct {
	DID              string    `gorm:"column:did;primaryKey;index:idx_operations_did_created_at,priority:1"`
	CID              string    `gorm:"column:cid;primaryKey"`
	CreatedAt        time.Time `gorm:"column:created_at;not null;index:idx_operations_did_created_at,priority:2"`
	Nullified        bool      `gorm:"column:nullified;not null;default:0"`
	LastChild        string    `gorm:"column:last_child"`
	AllowedKeysCount int       `gorm:"column:allowed_keys_count;not null"`
	OpData           opEnumDB  `gorm:"column:op_data;not null"`
}

// Note: couldn't call the type Operation because that'd get confusing with didplc.Operation
func (OperationRecord) TableName() string {
	return "operations"
}

// for tracking the ingest cursor
type HostCursor struct {
	Host string `gorm:"primaryKey"`
	Seq  int64  `gorm:"not null"`
}

// GormOpStore implements didplc.OpStore using a database backend
type GormOpStore struct {
	db *gorm.DB
}

var _ didplc.OpStore = (*GormOpStore)(nil)

// NewGormOpStoreWithDialector creates a new database-backed operation store with a custom dialector
func NewGormOpStoreWithDialector(dialector gorm.Dialector, logger *slog.Logger) (*GormOpStore, error) {
	db, err := gorm.Open(dialector, &gorm.Config{
		SkipDefaultTransaction: true,
		//PrepareStmt:            true, // Doesn't seem to work well with postgres
		Logger: slogGorm.New(
			slogGorm.WithHandler(logger.With("component", "opstore").Handler()),
			slogGorm.WithTraceAll(),
			slogGorm.SetLogLevel(slogGorm.DefaultLogType, slog.LevelDebug),
			slogGorm.SetLogLevel(slogGorm.SlowQueryLogType, slog.LevelWarn),
			slogGorm.SetLogLevel(slogGorm.ErrorLogType, slog.LevelError),
		),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database handle: %w", err)
	}

	sqlDB.SetMaxOpenConns(40) // with postgres, seems like less can be more...
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetConnMaxLifetime(time.Hour)

	// Auto-migrate the schema
	if err := db.AutoMigrate(&Head{}, &OperationRecord{}, &HostCursor{}); err != nil {
		return nil, fmt.Errorf("failed to migrate schema: %w", err)
	}

	return &GormOpStore{
		db: db,
	}, nil
}

func NewGormOpStoreWithSqlite(dbPath string, logger *slog.Logger) (*GormOpStore, error) {
	return NewGormOpStoreWithDialector(
		sqlite.Open(dbPath+"?mode=rwc&cache=shared&_journal_mode=WAL"),
		logger,
	)
}

func NewGormOpStoreWithPostgres(dsn string, logger *slog.Logger) (*GormOpStore, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to parse postgres URL: %w", err)
	}
	q := u.Query()
	if !q.Has("synchronous_commit") {
		// Since we're a replica, if we lose data we can just re-fetch it from the origin.
		q.Set("synchronous_commit", "off")
	}
	u.RawQuery = q.Encode()
	return NewGormOpStoreWithDialector(
		postgres.Open(u.String()),
		logger,
	)
}

// GetLatest implements didplc.OpStore
func (db *GormOpStore) GetLatest(ctx context.Context, did string) (*didplc.OpEntry, error) {
	var opRec OperationRecord
	result := db.db.WithContext(ctx).
		Joins("JOIN heads ON heads.did = operations.did AND heads.cid = operations.cid").
		Where("operations.did = ?", did).
		Take(&opRec)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, nil // DID not found
		}
		return nil, fmt.Errorf("database error: %w", result.Error)
	}

	opData := didplc.OpEnum(opRec.OpData)
	operation := opData.AsOperation()
	if operation == nil {
		return nil, fmt.Errorf("invalid operation type")
	}

	rotationKeys := operation.EquivalentRotationKeys()
	allowedKeys := rotationKeys[:opRec.AllowedKeysCount]

	return &didplc.OpEntry{
		DID:         opRec.DID,
		CreatedAt:   opRec.CreatedAt,
		Nullified:   opRec.Nullified,
		LastChild:   opRec.LastChild,
		AllowedKeys: allowedKeys,
		Op:          operation,
		OpCid:       opRec.CID,
	}, nil
}

// GetEntry implements didplc.OpStore
func (db *GormOpStore) GetEntry(ctx context.Context, did string, cid string) (*didplc.OpEntry, error) {
	var opRec OperationRecord
	result := db.db.WithContext(ctx).Where("did = ? AND cid = ?", did, cid).Take(&opRec)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("database error: %w", result.Error)
	}

	// Get rotation keys from the operation
	opData := didplc.OpEnum(opRec.OpData)
	operation := opData.AsOperation()
	if operation == nil {
		return nil, fmt.Errorf("invalid operation type")
	}

	// Get rotation keys and slice to allowed count
	rotationKeys := operation.EquivalentRotationKeys()
	allowedKeys := rotationKeys[:opRec.AllowedKeysCount]

	return &didplc.OpEntry{
		DID:         opRec.DID,
		CreatedAt:   opRec.CreatedAt,
		Nullified:   opRec.Nullified,
		LastChild:   opRec.LastChild,
		AllowedKeys: allowedKeys,
		Op:          operation,
		OpCid:       cid,
	}, nil
}

// GetAllEntries implements didplc.OpStore
func (db *GormOpStore) GetAllEntries(ctx context.Context, did string) ([]*didplc.OpEntry, error) {
	var opRecs []OperationRecord
	result := db.db.WithContext(ctx).Where("did = ?", did).Order("created_at ASC").Find(&opRecs)
	if result.Error != nil {
		return nil, fmt.Errorf("database error: %w", result.Error)
	}

	entries := make([]*didplc.OpEntry, 0, len(opRecs))
	for _, opRec := range opRecs {
		opData := didplc.OpEnum(opRec.OpData)
		operation := opData.AsOperation()
		if operation == nil {
			return nil, fmt.Errorf("invalid operation type")
		}
		rotationKeys := operation.EquivalentRotationKeys()
		allowedKeys := rotationKeys[:opRec.AllowedKeysCount]

		entries = append(entries, &didplc.OpEntry{
			DID:         opRec.DID,
			CreatedAt:   opRec.CreatedAt,
			Nullified:   opRec.Nullified,
			LastChild:   opRec.LastChild,
			AllowedKeys: allowedKeys,
			Op:          operation,
			OpCid:       opRec.CID,
		})
	}

	return entries, nil
}

// CommitOperations implements didplc.OpStore
func (db *GormOpStore) CommitOperations(ctx context.Context, ops []*didplc.PreparedOperation) error {
	// Begin transaction
	return db.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, prepOp := range ops {
			opData := opEnumDB(*prepOp.Op.AsOpEnum())

			if prepOp.PrevHead == "" {
				// Genesis operation
				// Insert new operation
				newOp := OperationRecord{
					DID:              prepOp.DID,
					CID:              prepOp.OpCid,
					CreatedAt:        prepOp.CreatedAt,
					Nullified:        false,
					LastChild:        "",
					AllowedKeysCount: len(prepOp.Op.EquivalentRotationKeys()),
					OpData:           opData,
				}
				if err := tx.Create(&newOp).Error; err != nil {
					return fmt.Errorf("failed to create operation: %w", err)
				}

				// Insert new head
				newHead := Head{
					DID: prepOp.DID,
					CID: prepOp.OpCid,
				}
				if err := tx.Create(&newHead).Error; err != nil {
					return fmt.Errorf("failed to create head: %w", err)
				}
			} else {
				// Non-genesis operation
				// Mark nullified operations
				for _, nullifiedCid := range prepOp.NullifiedOps {
					if err := tx.Model(&OperationRecord{}).Where("did = ? AND cid = ?", prepOp.DID, nullifiedCid).Update("nullified", true).Error; err != nil {
						return fmt.Errorf("failed to mark operation as nullified: %w", err)
					}
				}

				// Update previous operation's last_child and allowed_keys_count
				if err := tx.Model(&OperationRecord{}).Where("did = ? AND cid = ?", prepOp.DID, prepOp.Op.PrevCIDStr()).Updates(map[string]interface{}{
					"last_child":         prepOp.OpCid,
					"allowed_keys_count": prepOp.KeyIndex,
				}).Error; err != nil {
					return fmt.Errorf("failed to update previous operation: %w", err)
				}

				// Insert new operation
				newOp := OperationRecord{
					DID:              prepOp.DID,
					CID:              prepOp.OpCid,
					CreatedAt:        prepOp.CreatedAt,
					Nullified:        false,
					LastChild:        "",
					AllowedKeysCount: len(prepOp.Op.EquivalentRotationKeys()),
					OpData:           opData,
				}
				if err := tx.Create(&newOp).Error; err != nil {
					return fmt.Errorf("failed to create operation: %w", err)
				}

				// Update head with optimistic locking check
				result := tx.Model(&Head{}).Where("did = ? AND cid = ?", prepOp.DID, prepOp.PrevHead).Update("cid", prepOp.OpCid)
				if result.Error != nil {
					return fmt.Errorf("failed to update head: %w", result.Error)
				} else if result.RowsAffected != 1 {
					return fmt.Errorf("head CID mismatch")
				}
			}
		}

		return nil
	})
}

func (db *GormOpStore) PutCursor(ctx context.Context, host string, seq int64) error {
	// upsert
	result := db.db.WithContext(ctx).Clauses(clause.OnConflict{
		UpdateAll: true,
	}).Create(&HostCursor{
		Host: host,
		Seq:  seq,
	})
	return result.Error
}

// returns 0 if not found (since new hosts should start from 0)
func (db *GormOpStore) GetCursor(ctx context.Context, host string) (int64, error) {
	var hostCursor HostCursor
	result := db.db.WithContext(ctx).Where("host = ?", host).Take(&hostCursor)
	if result.Error == gorm.ErrRecordNotFound {
		return 0, nil
	}
	if result.Error != nil {
		return 0, result.Error
	}
	return hostCursor.Seq, nil
}
