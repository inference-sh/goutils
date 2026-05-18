package id

import (
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"time"

	"github.com/anandvarma/namegen"
	"github.com/oklog/ulid/v2"
)

func GenerateLexicalID() string {
	entropy := ulid.Monotonic(rand.Reader, 0)
	return strings.ToLower(ulid.MustNew(ulid.Timestamp(time.Now()), entropy).String())
}

func GenerateID() string {
	var id ulid.ULID
	_, _ = rand.Read(id[:])
	return strings.ToLower(id.String())
}

func GenerateULID() string {
	return strings.ToLower(ulid.Make().String())
}

// GenerateSeededID generates a deterministic ID based on a seed string (e.g. 3rd party user ID)
func GenerateSeededID(seed string) string {
	// Create a deterministic hash from the seed
	hash := sha256.Sum256([]byte(seed))
	var id ulid.ULID
	copy(id[:], hash[:]) // Copy first 16 bytes of hash into ULID
	return strings.ToLower(id.String())
}

// ShortContainerID truncates a Docker container ID to 12 characters,
// matching Docker's own short ID format. Docker APIs accept short IDs.
func ShortContainerID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// GenerateShortID generates a short, URL-safe ID (like nanoid)
// Default length is 4 characters (36^4 = 1.6M combinations)
// Alphabet is lowercase alphanumeric only (a-z, 0-9) for ease of use
func GenerateShortID(length int) string {
	if length <= 0 {
		length = 4
	}
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
	bytes := make([]byte, length)
	_, _ = rand.Read(bytes)
	for i := range bytes {
		bytes[i] = alphabet[bytes[i]%byte(len(alphabet))]
	}
	return string(bytes)
}

// NewSessionID generates a session ID with the format "sess_<ulid>"
func NewSessionID() string {
	return GenerateID()
}

// NewBaseModel creates a new BaseModel with auto-generated ID and ShortID
// Use this instead of models.BaseModel{ID: utils.GenerateID()} to ensure ShortID is set
func GenerateIDAndShortID() (id string, shortID string) {
	id = GenerateID()
	shortID = id[:8]
	return id, shortID
}

// GenerateUsername generates a human-readable username using a combination of adjective and noun
// If a seed is provided, it will be used to create a deterministic but still readable username

func GenerateUsername(seed string) string {
	// Create a name generator with adjective-color-animal pattern
	nameSchema := []namegen.DictType{
		namegen.Adjectives,
		namegen.Colors,
		namegen.Animals,
	}
	ngen := namegen.NewWithPostfixId(nameSchema, namegen.Numeric, 4)

	// Get a random username
	username := ngen.Get()

	// If no username was generated (very unlikely), fall back to the old method
	if username == "" {
		hash := sha256.Sum256([]byte(seed))
		var id ulid.ULID
		copy(id[:], hash[:])
		return strings.ToLower(id.String())
	}

	return username
}
