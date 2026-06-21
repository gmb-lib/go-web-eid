package certificate

import (
	"testing"

	"github.com/go-quicktest/qt"
)

func TestTitleCase(t *testing.T) {
	cases := map[string]string{
		"JAAK-KRISTJAN": "Jaak-Kristjan",
		"JÕEORG":        "Jõeorg",
		"MARY ANN":      "Mary Ann",
		"O'BRIEN":       "O'Brien",
		"":              "",
	}
	for in, want := range cases {
		qt.Check(t, qt.Equals(TitleCase(in), want))
	}
}
