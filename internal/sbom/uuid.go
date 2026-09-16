package sbom

import (
	"crypto/rand"
	"fmt"
)

// NewSerialNumber generates a random UUID v4 (RFC 4122), formatted as a
// urn:uuid: string suitable for a CycloneDX BOM's serialNumber field.
func NewSerialNumber() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}

	// Set the 4 version bits to 0100 (version 4 == random) and the 2
	// variant bits to 10 (RFC 4122 variant), per the spec.
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80

	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
