package webeid

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"time"
)

const (
	// minNonceBytes is the minimum nonce entropy in bytes (256 bits).
	minNonceBytes = 32
	// DefaultNonceTTL is the default challenge-nonce lifetime.
	DefaultNonceTTL = 5 * time.Minute
)

// ChallengeNonceGenerator creates and stores challenge nonces.
type ChallengeNonceGenerator interface {
	// GenerateAndStoreNonce creates a >=256-bit nonce, stores it via the
	// configured store and returns it.
	GenerateAndStoreNonce(ctx context.Context) (*ChallengeNonce, error)
}

// challengeNonceGenerator is the default ChallengeNonceGenerator.
//
// Nonce TTL is not held here: expiry is recorded as IssuedAt and enforced by
// the store / handler using the configured TTL.
type challengeNonceGenerator struct {
	store     ChallengeNonceStore
	nonceSize int
	random    io.Reader
	now       func() time.Time
}

// GenerateAndStoreNonce implements ChallengeNonceGenerator.
func (g *challengeNonceGenerator) GenerateAndStoreNonce(ctx context.Context) (*ChallengeNonce, error) {
	buf := make([]byte, g.nonceSize)
	if _, err := io.ReadFull(g.random, buf); err != nil {
		return nil, err
	}
	nonce := &ChallengeNonce{
		Base64EncodedNonce: base64.StdEncoding.EncodeToString(buf),
		IssuedAt:           g.now(),
	}
	if err := g.store.Put(ctx, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

// ChallengeNonceGeneratorBuilder builds a ChallengeNonceGenerator. It mirrors
// the Java ChallengeNonceGeneratorBuilder.
type ChallengeNonceGeneratorBuilder struct {
	store     ChallengeNonceStore
	ttl       time.Duration
	nonceSize int
	random    io.Reader
	now       func() time.Time
}

// NewChallengeNonceGeneratorBuilder returns a builder with default settings.
func NewChallengeNonceGeneratorBuilder() *ChallengeNonceGeneratorBuilder {
	return &ChallengeNonceGeneratorBuilder{
		ttl:       DefaultNonceTTL,
		nonceSize: minNonceBytes,
		random:    rand.Reader,
		now:       time.Now,
	}
}

// WithChallengeNonceStore sets the store used to persist nonces (required).
func (b *ChallengeNonceGeneratorBuilder) WithChallengeNonceStore(store ChallengeNonceStore) *ChallengeNonceGeneratorBuilder {
	b.store = store
	return b
}

// WithNonceTTL sets the nonce lifetime. Expiry is enforced by the store and the
// login handler using this TTL; the generator only records IssuedAt.
func (b *ChallengeNonceGeneratorBuilder) WithNonceTTL(ttl time.Duration) *ChallengeNonceGeneratorBuilder {
	if ttl > 0 {
		b.ttl = ttl
	}
	return b
}

// WithNonceSize overrides the nonce size in bytes. Values below 32 (256 bits)
// are clamped to 32.
func (b *ChallengeNonceGeneratorBuilder) WithNonceSize(bytes int) *ChallengeNonceGeneratorBuilder {
	if bytes >= minNonceBytes {
		b.nonceSize = bytes
	}
	return b
}

// WithSecureRandom overrides the entropy source (primarily for testing).
func (b *ChallengeNonceGeneratorBuilder) WithSecureRandom(r io.Reader) *ChallengeNonceGeneratorBuilder {
	if r != nil {
		b.random = r
	}
	return b
}

// Build validates the configuration and returns the generator.
func (b *ChallengeNonceGeneratorBuilder) Build() (ChallengeNonceGenerator, error) {
	if b.store == nil {
		return nil, errStoreNil
	}
	if b.ttl <= 0 {
		b.ttl = DefaultNonceTTL
	}
	return &challengeNonceGenerator{
		store:     b.store,
		nonceSize: b.nonceSize,
		random:    b.random,
		now:       b.now,
	}, nil
}
