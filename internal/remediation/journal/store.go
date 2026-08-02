package journal

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/conflict"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/stateroot"
)

const (
	journalFileName  = "journal.json"
	walFileName      = "journal.wal"
	maximumWALRecord = 64 << 20
)

var (
	runIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,191}$`)
	rootLocks    sync.Map
)

type WALRecord struct {
	SchemaVersion  int                      `json:"schema_version"`
	RunID          string                   `json:"run_id"`
	Revision       uint64                   `json:"revision"`
	PreviousDigest string                   `json:"previous_digest,omitempty"`
	Journal        model.RemediationJournal `json:"journal"`
	Digest         string                   `json:"digest"`
}

type walPayload struct {
	SchemaVersion  int                      `json:"schema_version"`
	RunID          string                   `json:"run_id"`
	Revision       uint64                   `json:"revision"`
	PreviousDigest string                   `json:"previous_digest,omitempty"`
	Journal        model.RemediationJournal `json:"journal"`
}

type Store struct {
	root string
	lock *sync.Mutex
	now  func() time.Time
}

type loadedRecord struct {
	journal model.RemediationJournal
	digest  string
}

type Inspection struct {
	Journal           *model.RemediationJournal
	IncompleteWALTail bool
}

func New(root string) (*Store, error) {
	return NewStore(root)
}

func NewStore(root string) (*Store, error) {
	absolute, err := stateroot.Prepare(root)
	if err != nil {
		return nil, wrap(CodeUnsafePath, "initialize journal store", "", err)
	}
	return newStoreAt(absolute), nil
}

func OpenExisting(root string) (*Store, error) {
	absolute, err := stateroot.Validate(root)
	if err != nil {
		return nil, wrap(CodeUnsafePath, "open existing journal store", "", err)
	}
	return newStoreAt(absolute), nil
}

func newStoreAt(absolute string) *Store {
	lockValue, _ := rootLocks.LoadOrStore(absolute, &sync.Mutex{})
	return &Store{
		root: absolute,
		lock: lockValue.(*sync.Mutex),
		now:  time.Now,
	}
}

func (s *Store) Root() string {
	if s == nil {
		return ""
	}
	return s.root
}

func (s *Store) Create(ctx context.Context, journal *model.RemediationJournal) error {
	if s == nil || journal == nil {
		return wrap(CodeInvalidInput, "create journal", "", fmt.Errorf("store and journal are required"))
	}
	if err := ctx.Err(); err != nil {
		return wrap(CodePersistFailed, "create journal", journal.RunID, err)
	}
	if err := validateRunID(journal.RunID); err != nil {
		return err
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	created, err := cloneJournal(journal)
	if err != nil {
		return wrap(CodeInvalidInput, "clone journal", journal.RunID, err)
	}
	if created.SchemaVersion == 0 {
		created.SchemaVersion = model.RemediationSchemaVersion
	}
	if created.Revision != 0 && created.Revision != 1 {
		return wrap(CodeInvalidInput, "create journal", created.RunID, fmt.Errorf("initial revision must be zero or one"))
	}
	created.Revision = 1
	now := s.now().UTC()
	if created.StartedAt.IsZero() {
		created.StartedAt = now
	} else {
		created.StartedAt = created.StartedAt.UTC()
	}
	if created.UpdatedAt.IsZero() {
		created.UpdatedAt = created.StartedAt
	} else {
		created.UpdatedAt = created.UpdatedAt.UTC()
	}
	if err := created.Validate(); err != nil {
		return wrap(CodeInvalidInput, "create journal", created.RunID, err)
	}
	if err := validateInitialJournal(created); err != nil {
		return wrap(CodeInvalidInput, "create journal", created.RunID, err)
	}
	if err := conflict.Validate(created.ConflictGraph); err != nil {
		return wrap(CodeInvalidInput, "create journal", created.RunID, err)
	}

	runDirectory := s.runDirectory(created.RunID)
	if _, err := os.Lstat(runDirectory); err == nil {
		return wrap(CodeAlreadyExists, "create journal", created.RunID, fmt.Errorf("journal directory already exists"))
	} else if !errors.Is(err, os.ErrNotExist) {
		return wrap(CodeUnsafePath, "inspect journal directory", created.RunID, err)
	}
	temporaryDirectory, err := os.MkdirTemp(s.root, ".creating-")
	if err != nil {
		return wrap(CodePersistFailed, "create temporary journal directory", created.RunID, err)
	}
	published := false
	defer func() {
		if published {
			return
		}
		_ = os.RemoveAll(temporaryDirectory)
		_ = syncDirectory(s.root)
	}()
	if err := os.Chmod(temporaryDirectory, 0o700); err != nil {
		return wrap(CodePersistFailed, "secure temporary journal directory", created.RunID, err)
	}

	record, err := makeRecord(*created, "")
	if err != nil {
		return wrap(CodePersistFailed, "encode initial WAL record", created.RunID, err)
	}
	if err := writeInitialWAL(filepath.Join(temporaryDirectory, walFileName), record); err != nil {
		return wrap(CodePersistFailed, "write initial WAL record", created.RunID, err)
	}
	if err := syncDirectory(temporaryDirectory); err != nil {
		return wrap(CodePersistFailed, "sync journal directory", created.RunID, err)
	}
	if err := writeSnapshotAtomic(temporaryDirectory, *created); err != nil {
		return wrap(CodePersistFailed, "write initial journal snapshot", created.RunID, err)
	}
	if err := os.Rename(temporaryDirectory, runDirectory); err != nil {
		if _, statErr := os.Lstat(runDirectory); statErr == nil {
			return wrap(CodeAlreadyExists, "publish journal", created.RunID, err)
		}
		return wrap(CodePersistFailed, "publish journal", created.RunID, err)
	}
	published = true
	if err := syncDirectory(s.root); err != nil {
		return &Error{
			Code:      CodePersistFailed,
			Operation: "sync published journal",
			RunID:     created.RunID,
			Committed: true,
			Err:       err,
		}
	}
	return nil
}

func (s *Store) Load(ctx context.Context, runID string) (*model.RemediationJournal, error) {
	if s == nil {
		return nil, wrap(CodeInvalidInput, "load journal", runID, fmt.Errorf("store is required"))
	}
	if err := validateRunID(runID); err != nil {
		return nil, err
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	if err := s.validateRunDirectory(runID); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, wrap(CodeNotFound, "inspect journal directory", runID, err)
		}
		return nil, wrap(CodeUnsafePath, "inspect journal directory", runID, err)
	}
	unlock, err := acquireFileLock(ctx, filepath.Join(s.runDirectory(runID), ".journal.lock"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, wrap(CodeNotFound, "lock journal", runID, err)
		}
		return nil, wrap(CodePersistFailed, "lock journal", runID, err)
	}
	defer unlock()
	loaded, err := s.loadLocked(ctx, runID)
	if err != nil {
		return nil, err
	}
	return cloneJournal(&loaded.journal)
}

func (s *Store) LoadReadOnly(ctx context.Context, runID string) (*model.RemediationJournal, error) {
	inspection, err := s.Inspect(ctx, runID)
	if err != nil {
		return nil, err
	}
	return inspection.Journal, nil
}

func (s *Store) Inspect(ctx context.Context, runID string) (Inspection, error) {
	if s == nil {
		return Inspection{}, wrap(CodeInvalidInput, "inspect journal", runID, fmt.Errorf("store is required"))
	}
	if err := validateRunID(runID); err != nil {
		return Inspection{}, err
	}
	if err := ctx.Err(); err != nil {
		return Inspection{}, wrap(CodePersistFailed, "inspect journal", runID, err)
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	if err := s.validateRunDirectory(runID); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Inspection{}, wrap(CodeNotFound, "inspect journal directory", runID, err)
		}
		return Inspection{}, wrap(CodeUnsafePath, "inspect journal directory", runID, err)
	}
	walPath := filepath.Join(s.runDirectory(runID), walFileName)
	if err := validateRegularFile(walPath, 0o600); err != nil {
		return Inspection{}, wrap(CodeUnsafePath, "inspect WAL", runID, err)
	}
	record, _, incomplete, err := readWAL(ctx, walPath, runID)
	if err != nil {
		return Inspection{}, err
	}
	journalValue, err := cloneJournal(&record.Journal)
	if err != nil {
		return Inspection{}, wrap(CodePersistFailed, "clone inspected journal", runID, err)
	}
	return Inspection{Journal: journalValue, IncompleteWALTail: incomplete}, nil
}

func (s *Store) Update(
	ctx context.Context,
	runID string,
	expectedRevision uint64,
	mutate func(*model.RemediationJournal) error,
) (*model.RemediationJournal, error) {
	if s == nil || mutate == nil {
		return nil, wrap(CodeInvalidInput, "update journal", runID, fmt.Errorf("store and mutation callback are required"))
	}
	if err := validateRunID(runID); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, wrap(CodePersistFailed, "update journal", runID, err)
	}

	s.lock.Lock()
	defer s.lock.Unlock()
	if err := s.validateRunDirectory(runID); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, wrap(CodeNotFound, "inspect journal directory", runID, err)
		}
		return nil, wrap(CodeUnsafePath, "inspect journal directory", runID, err)
	}
	unlock, err := acquireFileLock(ctx, filepath.Join(s.runDirectory(runID), ".journal.lock"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, wrap(CodeNotFound, "lock journal", runID, err)
		}
		return nil, wrap(CodePersistFailed, "lock journal", runID, err)
	}
	defer unlock()

	loaded, err := s.loadLocked(ctx, runID)
	if err != nil {
		return nil, err
	}
	if loaded.journal.Revision != expectedRevision {
		return nil, &Error{
			Code:             CodeRevisionConflict,
			Operation:        "update journal",
			RunID:            runID,
			ExpectedRevision: expectedRevision,
			ActualRevision:   loaded.journal.Revision,
		}
	}
	if expectedRevision == math.MaxUint64 {
		return nil, wrap(CodeInvalidInput, "update journal", runID, fmt.Errorf("journal revision is exhausted"))
	}

	next, err := cloneJournal(&loaded.journal)
	if err != nil {
		return nil, wrap(CodePersistFailed, "clone journal", runID, err)
	}
	if err := mutate(next); err != nil {
		return nil, wrap(CodeInvalidInput, "mutate journal", runID, err)
	}
	if next.Revision != loaded.journal.Revision {
		return nil, wrap(CodeInvalidTransition, "update journal", runID, fmt.Errorf("mutation callback cannot change revision"))
	}
	next.Revision++
	now, err := updatedAtAfterJournalEvents(s.now().UTC(), next)
	if err != nil {
		return nil, wrap(CodeInvalidInput, "update journal", runID, err)
	}
	next.UpdatedAt = now
	if err := ValidateTransition(&loaded.journal, next); err != nil {
		return nil, err
	}

	record, err := makeRecord(*next, loaded.digest)
	if err != nil {
		return nil, wrap(CodePersistFailed, "encode WAL record", runID, err)
	}
	runDirectory := s.runDirectory(runID)
	walCommitted, err := appendWAL(filepath.Join(runDirectory, walFileName), record)
	if err != nil {
		if walCommitted {
			return next, &Error{
				Code:      CodePersistFailed,
				Operation: "close committed WAL record",
				RunID:     runID,
				Committed: true,
				Err:       err,
			}
		}
		return nil, wrap(CodePersistFailed, "append WAL record", runID, err)
	}
	if err := writeSnapshotAtomic(runDirectory, *next); err != nil {
		committed, cloneErr := cloneJournal(next)
		if cloneErr != nil {
			committed = next
		}
		return committed, &Error{
			Code:      CodePersistFailed,
			Operation: "write journal snapshot",
			RunID:     runID,
			Committed: true,
			Err:       err,
		}
	}
	return cloneJournal(next)
}

func updatedAtAfterJournalEvents(now time.Time, journal *model.RemediationJournal) (time.Time, error) {
	if journal == nil {
		return time.Time{}, fmt.Errorf("journal is required")
	}
	latestEvent := journal.LatestEventTime()
	if now.After(latestEvent) {
		return now, nil
	}
	next := latestEvent.Add(time.Nanosecond)
	if !next.After(latestEvent) {
		return time.Time{}, fmt.Errorf("journal event timestamp is exhausted")
	}
	return next, nil
}

func (s *Store) ListRecoverable(ctx context.Context) ([]model.RemediationJournal, error) {
	if s == nil {
		return nil, wrap(CodeInvalidInput, "list recoverable journals", "", fmt.Errorf("store is required"))
	}
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, wrap(CodePersistFailed, "list journal root", "", err)
	}
	result := make([]model.RemediationJournal, 0)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, wrap(CodePersistFailed, "list recoverable journals", "", err)
		}
		if entry.Name() == "payloads" || !entry.IsDir() || !runIDPattern.MatchString(entry.Name()) {
			continue
		}
		inspection, err := s.Inspect(ctx, entry.Name())
		if err != nil {
			return nil, err
		}
		if inspection.IncompleteWALTail {
			return nil, wrap(CodeCorruptWAL, "list recoverable journals", entry.Name(), fmt.Errorf("journal has an incomplete WAL tail; explicit recovery is required"))
		}
		journal := inspection.Journal
		if !journal.State.Terminal() || journal.State.NeedsOperatorAction() {
			result = append(result, *journal)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].StartedAt.Equal(result[j].StartedAt) {
			return result[i].RunID < result[j].RunID
		}
		return result[i].StartedAt.Before(result[j].StartedAt)
	})
	return result, nil
}

func (s *Store) loadLocked(ctx context.Context, runID string) (loadedRecord, error) {
	if err := ctx.Err(); err != nil {
		return loadedRecord{}, wrap(CodePersistFailed, "load journal", runID, err)
	}
	runDirectory := s.runDirectory(runID)
	if err := s.validateRunDirectory(runID); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return loadedRecord{}, wrap(CodeNotFound, "load journal", runID, err)
		}
		return loadedRecord{}, wrap(CodeUnsafePath, "inspect journal directory", runID, err)
	}

	walPath := filepath.Join(runDirectory, walFileName)
	if err := validateRegularFile(walPath, 0o600); err != nil {
		return loadedRecord{}, wrap(CodeUnsafePath, "inspect WAL", runID, err)
	}
	record, validEnd, incomplete, err := readWAL(ctx, walPath, runID)
	if err != nil {
		return loadedRecord{}, err
	}
	if incomplete {
		if err := truncateWAL(walPath, validEnd); err != nil {
			return loadedRecord{}, wrap(CodePersistFailed, "truncate incomplete WAL tail", runID, err)
		}
		if err := syncDirectory(runDirectory); err != nil {
			return loadedRecord{}, wrap(CodePersistFailed, "sync recovered WAL", runID, err)
		}
	}
	if err := reconcileSnapshot(runDirectory, record.Journal); err != nil {
		return loadedRecord{}, wrap(CodePersistFailed, "reconcile journal snapshot", runID, err)
	}
	return loadedRecord{journal: record.Journal, digest: record.Digest}, nil
}

func readWAL(ctx context.Context, path, runID string) (WALRecord, int64, bool, error) {
	file, err := openPrivateRegular(path, os.O_RDONLY)
	if err != nil {
		return WALRecord{}, 0, false, wrap(CodePersistFailed, "open WAL", runID, err)
	}
	defer file.Close()

	reader := bufio.NewReaderSize(file, 64<<10)
	var previous WALRecord
	var validEnd int64
	var consumed int64
	recordCount := 0
	for {
		if err := ctx.Err(); err != nil {
			return WALRecord{}, validEnd, false, wrap(CodePersistFailed, "read WAL", runID, err)
		}
		line, complete, bytesRead, err := readWALLine(reader)
		consumed += int64(bytesRead)
		if err != nil {
			return WALRecord{}, validEnd, false, wrap(CodeCorruptWAL, "read WAL", runID, err)
		}
		if len(line) == 0 && !complete {
			break
		}
		if !complete {
			if recordCount == 0 {
				return WALRecord{}, 0, false, wrap(CodeCorruptWAL, "read WAL", runID, fmt.Errorf("WAL contains no complete record"))
			}
			return previous, validEnd, true, nil
		}
		record, err := decodeAndValidateRecord(line, runID, previous, recordCount)
		if err != nil {
			return WALRecord{}, validEnd, false, err
		}
		previous = record
		recordCount++
		validEnd = consumed
	}
	if recordCount == 0 {
		return WALRecord{}, 0, false, wrap(CodeCorruptWAL, "read WAL", runID, fmt.Errorf("WAL is empty"))
	}
	return previous, validEnd, false, nil
}

func readWALLine(reader *bufio.Reader) ([]byte, bool, int, error) {
	var line []byte
	consumed := 0
	for {
		fragment, err := reader.ReadSlice('\n')
		consumed += len(fragment)
		line = append(line, fragment...)
		if len(line) > maximumWALRecord {
			return nil, false, consumed, fmt.Errorf("WAL record exceeds %d bytes", maximumWALRecord)
		}
		switch {
		case err == nil:
			return line[:len(line)-1], true, consumed, nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			return line, false, consumed, nil
		default:
			return nil, false, consumed, err
		}
	}
}

func decodeAndValidateRecord(line []byte, runID string, previous WALRecord, index int) (WALRecord, error) {
	if len(bytes.TrimSpace(line)) == 0 {
		return WALRecord{}, wrap(CodeCorruptWAL, "decode WAL record", runID, fmt.Errorf("WAL contains a blank record"))
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	var record WALRecord
	if err := decoder.Decode(&record); err != nil {
		return WALRecord{}, wrap(CodeCorruptWAL, "decode WAL record", runID, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			err = fmt.Errorf("WAL record contains trailing JSON")
		}
		return WALRecord{}, wrap(CodeCorruptWAL, "decode WAL record", runID, err)
	}
	canonicalRecord, err := CanonicalJSON(record)
	if err != nil {
		return WALRecord{}, wrap(CodeCorruptWAL, "canonicalize WAL record", runID, err)
	}
	if !bytes.Equal(line, canonicalRecord) {
		return WALRecord{}, wrap(CodeCorruptWAL, "validate WAL encoding", runID, fmt.Errorf("WAL record is not canonical JSON"))
	}
	if record.SchemaVersion != record.Journal.SchemaVersion ||
		!model.IsSupportedRemediationSchemaVersion(record.SchemaVersion) {
		return WALRecord{}, wrap(CodeUnsupportedSchema, "validate WAL record", runID, fmt.Errorf("unsupported schema version"))
	}
	if record.RunID != runID || record.Journal.RunID != runID {
		return WALRecord{}, wrap(CodeCorruptWAL, "validate WAL record", runID, fmt.Errorf("record run id does not match its directory"))
	}
	if record.Revision != record.Journal.Revision {
		return WALRecord{}, wrap(CodeCorruptWAL, "validate WAL record", runID, fmt.Errorf("record revision and journal revision differ"))
	}
	if index == 0 {
		if record.Revision != 1 || record.PreviousDigest != "" {
			return WALRecord{}, wrap(CodeCorruptWAL, "validate WAL chain", runID, fmt.Errorf("initial WAL record is invalid"))
		}
		if err := validateInitialJournal(&record.Journal); err != nil {
			return WALRecord{}, wrap(CodeCorruptWAL, "validate initial journal", runID, err)
		}
	} else {
		if record.Revision != previous.Revision+1 || record.PreviousDigest != previous.Digest {
			return WALRecord{}, wrap(CodeCorruptWAL, "validate WAL chain", runID, fmt.Errorf("WAL revision or digest chain is broken"))
		}
	}
	expected, err := recordDigest(record)
	if err != nil {
		return WALRecord{}, wrap(CodeCorruptWAL, "digest WAL record", runID, err)
	}
	if !equalDigest(expected, record.Digest) {
		return WALRecord{}, wrap(CodeCorruptWAL, "validate WAL digest", runID, fmt.Errorf("WAL record digest does not match"))
	}
	if err := record.Journal.Validate(); err != nil {
		return WALRecord{}, wrap(CodeCorruptWAL, "validate journal payload", runID, err)
	}
	if err := conflict.Validate(record.Journal.ConflictGraph); err != nil {
		return WALRecord{}, wrap(CodeCorruptWAL, "validate conflict graph payload", runID, err)
	}
	if index > 0 {
		if err := ValidateTransition(&previous.Journal, &record.Journal); err != nil {
			return WALRecord{}, wrap(CodeCorruptWAL, "validate WAL state transition", runID, err)
		}
	}
	return record, nil
}

func makeRecord(journal model.RemediationJournal, previousDigest string) (WALRecord, error) {
	record := WALRecord{
		SchemaVersion:  journal.SchemaVersion,
		RunID:          journal.RunID,
		Revision:       journal.Revision,
		PreviousDigest: previousDigest,
		Journal:        journal,
	}
	digest, err := recordDigest(record)
	if err != nil {
		return WALRecord{}, err
	}
	record.Digest = digest
	return record, nil
}

func recordDigest(record WALRecord) (string, error) {
	payload := walPayload{
		SchemaVersion:  record.SchemaVersion,
		RunID:          record.RunID,
		Revision:       record.Revision,
		PreviousDigest: record.PreviousDigest,
		Journal:        record.Journal,
	}
	return Digest(payload)
}

func equalDigest(expected, actual string) bool {
	expectedBytes, expectedErr := hex.DecodeString(expected)
	actualBytes, actualErr := hex.DecodeString(actual)
	if expectedErr != nil || actualErr != nil || len(expectedBytes) != len(actualBytes) {
		return false
	}
	if hex.EncodeToString(expectedBytes) != expected || hex.EncodeToString(actualBytes) != actual {
		return false
	}
	return subtle.ConstantTimeCompare(expectedBytes, actualBytes) == 1
}

func writeInitialWAL(path string, record WALRecord) error {
	if err := ensureNonexistentOrRegular(path, false); err != nil {
		return err
	}
	directory := filepath.Dir(path)
	file, err := createTemporary(directory)
	if err != nil {
		return err
	}
	temporaryName := file.Name()
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
		_ = os.Remove(temporaryName)
	}()
	if err := writeRecord(file, record); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		closed = true
		return err
	}
	closed = true
	if err := os.Rename(temporaryName, path); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func appendWAL(path string, record WALRecord) (bool, error) {
	if err := validateRegularFile(path, 0o600); err != nil {
		return false, err
	}
	file, err := openPrivateRegular(path, os.O_WRONLY|os.O_APPEND)
	if err != nil {
		return false, err
	}
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
	}()
	if err := writeRecord(file, record); err != nil {
		return false, err
	}
	if err := file.Sync(); err != nil {
		return false, err
	}
	if err := file.Close(); err != nil {
		closed = true
		return true, err
	}
	closed = true
	return true, nil
}

func writeRecord(writer io.Writer, record WALRecord) error {
	encoded, err := CanonicalJSON(record)
	if err != nil {
		return err
	}
	if len(encoded)+1 > maximumWALRecord {
		return fmt.Errorf("WAL record exceeds %d bytes", maximumWALRecord)
	}
	encoded = append(encoded, '\n')
	return writeAll(writer, encoded)
}

func writeSnapshotAtomic(runDirectory string, journal model.RemediationJournal) error {
	path := filepath.Join(runDirectory, journalFileName)
	if err := ensureNonexistentOrRegular(path, true); err != nil {
		return err
	}
	encoded, err := CanonicalJSON(journal)
	if err != nil {
		return err
	}
	temporary, err := createTemporary(runDirectory)
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	closed := false
	defer func() {
		if !closed {
			_ = temporary.Close()
		}
		_ = os.Remove(temporaryName)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if err := writeAll(temporary, encoded); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	closed = true
	if err := os.Rename(temporaryName, path); err != nil {
		return err
	}
	return syncDirectory(runDirectory)
}

func createTemporary(directory string) (*os.File, error) {
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	name := ".journal-" + hex.EncodeToString(random) + ".tmp"
	return os.OpenFile(filepath.Join(directory, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}

func reconcileSnapshot(runDirectory string, journal model.RemediationJournal) error {
	path := filepath.Join(runDirectory, journalFileName)
	expected, err := CanonicalJSON(journal)
	if err != nil {
		return err
	}
	info, statErr := os.Lstat(path)
	if statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("journal snapshot is not a regular file")
		}
		if info.Mode().Perm() != 0o600 {
			return fmt.Errorf("journal snapshot permissions are %04o, expected 0600", info.Mode().Perm())
		}
		if err := validateOwner(info); err != nil {
			return err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	actual, err := readPrivateFile(path, maximumWALRecord)
	if err == nil && bytes.Equal(actual, expected) {
		return nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeSnapshotAtomic(runDirectory, journal)
}

func truncateWAL(path string, size int64) error {
	file, err := openPrivateRegular(path, os.O_RDWR)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := file.Truncate(size); err != nil {
		return err
	}
	return file.Sync()
}

func ensureNonexistentOrRegular(path string, allowExisting bool) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !allowExisting {
		return fmt.Errorf("path already exists")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("path is not a regular file")
	}
	if err := validateOwner(info); err != nil {
		return err
	}
	return nil
}

func validateRegularFile(path string, requiredMode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("path is not a regular file")
	}
	if info.Mode().Perm() != requiredMode.Perm() {
		return fmt.Errorf("file permissions are %04o, expected %04o", info.Mode().Perm(), requiredMode.Perm())
	}
	if err := validateOwner(info); err != nil {
		return err
	}
	return nil
}

func readPrivateFile(path string, limit int64) ([]byte, error) {
	file, err := openPrivateRegular(path, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > limit {
		return nil, fmt.Errorf("private file exceeds %d bytes", limit)
	}
	return content, nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil && runtime.GOOS != "windows" {
		return err
	}
	return nil
}

func cloneJournal(journal *model.RemediationJournal) (*model.RemediationJournal, error) {
	if journal == nil {
		return nil, fmt.Errorf("journal is required")
	}
	encoded, err := CanonicalJSON(journal)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var clone model.RemediationJournal
	if err := decoder.Decode(&clone); err != nil {
		return nil, err
	}
	return &clone, nil
}

func validateRunID(runID string) error {
	if !runIDPattern.MatchString(runID) {
		return wrap(CodeUnsafePath, "validate run id", runID, fmt.Errorf("run id contains unsupported characters or length"))
	}
	return nil
}

func validateInitialJournal(journal *model.RemediationJournal) error {
	if journal == nil || journal.State != model.RunPlanned || journal.Revision != 1 {
		return fmt.Errorf("initial journal must be revision 1 in planned state")
	}
	if len(journal.RollbackAttempts) != 0 || len(journal.UnresolvedChangeSets) != 0 || journal.Error != nil {
		return fmt.Errorf("initial journal cannot contain rollback or error state")
	}
	for _, changeSet := range journal.ChangeSets {
		if changeSet.State != model.ChangePlanned || changeSet.Approval != nil || len(changeSet.Before) != 0 || len(changeSet.After) != 0 {
			return fmt.Errorf("initial change set %s must be unapproved and planned", changeSet.ID)
		}
		if changeSet.PreparedAt != nil || changeSet.AppliedAt != nil || changeSet.VerifiedAt != nil || changeSet.RolledBackAt != nil || changeSet.Error != nil {
			return fmt.Errorf("initial change set %s contains runtime state", changeSet.ID)
		}
		for _, operation := range changeSet.Operations {
			if operation.State != model.OperationPlanned || !operation.Before.IsZero() || operation.ObservedAfter != nil || operation.ObservedRollback != nil || operation.Backup != nil || operation.Error != nil {
				return fmt.Errorf("initial operation %s contains runtime state", operation.ID)
			}
			if operation.ApplyIntentAt != nil || operation.AppliedAt != nil || operation.RollbackIntentAt != nil || operation.RolledBackAt != nil {
				return fmt.Errorf("initial operation %s contains runtime timestamps", operation.ID)
			}
		}
	}
	return nil
}

func (s *Store) runDirectory(runID string) string {
	return filepath.Join(s.root, runID)
}

func (s *Store) validateRunDirectory(runID string) error {
	info, err := os.Lstat(s.runDirectory(runID))
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return fmt.Errorf("journal directory must be a private real directory")
	}
	return validateOwner(info)
}
