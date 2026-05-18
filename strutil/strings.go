package strutil

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"regexp"

	"github.com/gosimple/slug"
)

// GenerateRandomString generates a random hex string of specified length
func GenerateRandomString(length int) (string, error) {
	bytes := make([]byte, length/2)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func Slugify(input string) string {
	return slug.Make(input)
}

func IsValidName(name string, regex string) bool {
	match, err := regexp.MatchString(regex, name)
	return match && err == nil
}

func IsValidEmail(email string) bool {
	return regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`).MatchString(email)
}

func HashString(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// Ptr returns a pointer to the given value.
func Ptr[T any](v T) *T { return &v }
