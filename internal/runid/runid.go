package runid

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

func New(prefix string, now time.Time) (string, error) {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("generate run id entropy: %w", err)
	}
	return fmt.Sprintf("%s-%s-%s", prefix, now.UTC().Format("20060102T150405.000000000Z"), hex.EncodeToString(random)), nil
}
