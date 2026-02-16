package metadata

import (
	"bytes"
	"testing"
)

func FuzzStripJPEGExif(f *testing.F) {
	// Valid JPEG prefix seeds
	f.Add([]byte{0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x10})
	f.Add([]byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x02, 0xFF, 0xDA, 0x00})
	f.Add([]byte{0xFF, 0xD8})
	f.Add([]byte{})

	s := NewScrubber()
	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic
		_ = s.stripJPEGExif(data)
	})
}

func FuzzStripPNGMetadata(f *testing.F) {
	// Valid PNG signature seed
	f.Add([]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A})
	f.Add([]byte{})

	s := NewScrubber()
	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic
		_ = s.stripPNGMetadata(data)
	})
}

func FuzzScrubFile(f *testing.F) {
	f.Add([]byte{0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x10}, true)
	f.Add([]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, false)
	f.Add([]byte{}, true)

	s := NewScrubber()
	f.Fuzz(func(t *testing.T, data []byte, isJPEG bool) {
		filename := "test.png"
		if isJPEG {
			filename = "test.jpg"
		}
		var buf bytes.Buffer
		// Must not panic
		_ = s.ScrubFile(filename, bytes.NewReader(data), &buf)
	})
}
