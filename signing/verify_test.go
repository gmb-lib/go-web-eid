package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func p1363(r, s *big.Int, curveBits int) []byte {
	byteLen := (curveBits + 7) / 8
	out := make([]byte, 2*byteLen)
	r.FillBytes(out[:byteLen])
	s.FillBytes(out[byteLen:])
	return out
}

func TestVerifySignatureValue_ECDSARoundtrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "TEST", SerialNumber: "PNOLV-1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256([]byte("data-to-be-signed"))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := p1363(r, s, key.Curve.Params().BitSize) // card-format raw r||s

	algo := SignatureAlgorithm{CryptoAlgorithm: "ECC", HashFunction: "SHA-256", PaddingScheme: "NONE"}

	if err := VerifySignatureValue(cert, algo, digest[:], sig); err != nil {
		t.Fatalf("valid card signature must verify: %v", err)
	}

	tampered := sha256.Sum256([]byte("different data"))
	if err := VerifySignatureValue(cert, algo, tampered[:], sig); err == nil {
		t.Fatal("tampered digest must fail verification")
	}

	if err := VerifySignatureValue(cert, algo, digest[:], sig[:len(sig)-1]); err == nil {
		t.Fatal("truncated P1363 signature must fail verification")
	}
}
