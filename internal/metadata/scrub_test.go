package metadata

import (
	"bytes"
	"testing"
)

func TestScrubFile_JPEG_MinimalValid(t *testing.T) {
	s := NewScrubber()

	// Minimal JPEG: SOI + APP1 (EXIF) + SOS + EOI
	jpeg := []byte{
		0xFF, 0xD8, // SOI
		0xFF, 0xE1, 0x00, 0x08, 'E', 'x', 'i', 'f', 0x00, 0x00, // APP1 with Exif
		0xFF, 0xDA, 0x00, 0x02, // SOS (Start of Scan)
		0xFF, 0xD9, // EOI
	}

	var out bytes.Buffer
	if err := s.ScrubFile("photo.jpg", bytes.NewReader(jpeg), &out); err != nil {
		t.Fatalf("ScrubFile error: %v", err)
	}

	result := out.Bytes()
	// SOI should be preserved
	if len(result) < 2 || result[0] != 0xFF || result[1] != 0xD8 {
		t.Error("JPEG SOI should be preserved")
	}

	// APP1 should be stripped
	if bytes.Contains(result, []byte("Exif")) {
		t.Error("EXIF data should be stripped")
	}
}

func TestScrubFile_JPEG_Extension(t *testing.T) {
	s := NewScrubber()
	jpeg := []byte{
		0xFF, 0xD8, // SOI
		0xFF, 0xE0, 0x00, 0x04, 0x00, 0x00, // APP0
		0xFF, 0xDA, 0x00, 0x02, // SOS
	}

	var out bytes.Buffer
	err := s.ScrubFile("photo.jpeg", bytes.NewReader(jpeg), &out)
	if err != nil {
		t.Fatalf("ScrubFile with .jpeg extension error: %v", err)
	}
}

func TestScrubFile_PNG_MinimalValid(t *testing.T) {
	s := NewScrubber()

	// Build a minimal PNG with tEXt chunk
	pngSig := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}

	// IHDR chunk (minimal)
	ihdr := buildPNGChunk("IHDR", make([]byte, 13))
	// tEXt chunk (metadata to strip)
	textData := []byte("Author\x00Test Author")
	text := buildPNGChunk("tEXt", textData)
	// IEND chunk
	iend := buildPNGChunk("IEND", nil)

	png := append(pngSig, ihdr...)
	png = append(png, text...)
	png = append(png, iend...)

	var out bytes.Buffer
	if err := s.ScrubFile("image.png", bytes.NewReader(png), &out); err != nil {
		t.Fatalf("ScrubFile error: %v", err)
	}

	result := out.Bytes()
	// PNG signature should be preserved
	if !bytes.HasPrefix(result, pngSig) {
		t.Error("PNG signature should be preserved")
	}

	// tEXt chunk should be stripped
	if bytes.Contains(result, []byte("tEXt")) {
		t.Error("tEXt chunk should be stripped")
	}

	// IHDR and IEND should be preserved
	if !bytes.Contains(result, []byte("IHDR")) {
		t.Error("IHDR chunk should be preserved")
	}
	if !bytes.Contains(result, []byte("IEND")) {
		t.Error("IEND chunk should be preserved")
	}
}

func TestScrubFile_UnsupportedType(t *testing.T) {
	s := NewScrubber()
	content := []byte("plain text content")

	var out bytes.Buffer
	if err := s.ScrubFile("document.txt", bytes.NewReader(content), &out); err != nil {
		t.Fatalf("ScrubFile error: %v", err)
	}

	if !bytes.Equal(out.Bytes(), content) {
		t.Error("unsupported file type should pass through unchanged")
	}
}

func TestScrubFile_UnknownExtension(t *testing.T) {
	s := NewScrubber()
	content := []byte("binary data")

	var out bytes.Buffer
	if err := s.ScrubFile("data.xyz", bytes.NewReader(content), &out); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(out.Bytes(), content) {
		t.Error("unknown extension should pass through unchanged")
	}
}

func TestIsMetadataPresent_ExifDetection(t *testing.T) {
	s := NewScrubber()
	data := []byte{0xFF, 0xD8, 0xFF, 0xE1, 'E', 'x', 'i', 'f'}
	if !s.IsMetadataPresent(data) {
		t.Error("should detect Exif metadata")
	}
}

func TestIsMetadataPresent_GPSDetection(t *testing.T) {
	s := NewScrubber()
	data := []byte("some data with GPS info")
	if !s.IsMetadataPresent(data) {
		t.Error("should detect GPS metadata")
	}
}

func TestIsMetadataPresent_PNGText(t *testing.T) {
	s := NewScrubber()
	data := []byte("...tEXt...")
	if !s.IsMetadataPresent(data) {
		t.Error("should detect tEXt chunk")
	}
}

func TestIsMetadataPresent_Clean(t *testing.T) {
	s := NewScrubber()
	data := []byte("clean data with no metadata markers")
	if s.IsMetadataPresent(data) {
		t.Error("clean data should not be flagged")
	}
}

func TestScrubFile_NotValidJPEG(t *testing.T) {
	s := NewScrubber()
	// Data claiming to be JPEG by extension but not valid
	data := []byte("not a jpeg at all")

	var out bytes.Buffer
	if err := s.ScrubFile("fake.jpg", bytes.NewReader(data), &out); err != nil {
		t.Fatal(err)
	}
	// Should pass through unchanged
	if !bytes.Equal(out.Bytes(), data) {
		t.Error("invalid JPEG should pass through unchanged")
	}
}

func TestScrubFile_NotValidPNG(t *testing.T) {
	s := NewScrubber()
	data := []byte("not a png at all")

	var out bytes.Buffer
	if err := s.ScrubFile("fake.png", bytes.NewReader(data), &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), data) {
		t.Error("invalid PNG should pass through unchanged")
	}
}

func TestScrubFile_JPEG_WithNonAppSegments(t *testing.T) {
	s := NewScrubber()
	// JPEG with a DQT segment (0xDB) followed by SOS
	jpeg := []byte{
		0xFF, 0xD8, // SOI
		0xFF, 0xDB, 0x00, 0x04, 0x00, 0x00, // DQT segment (non-APP)
		0xFF, 0xDA, 0x00, 0x02, // SOS
	}

	var out bytes.Buffer
	s.ScrubFile("test.jpg", bytes.NewReader(jpeg), &out)

	result := out.Bytes()
	// DQT should be preserved
	if !bytes.Contains(result, []byte{0xFF, 0xDB}) {
		t.Error("DQT segment should be preserved")
	}
}

func TestScrubFile_JPEG_NonMarkerByte(t *testing.T) {
	s := NewScrubber()
	// JPEG SOI followed by non-marker byte
	jpeg := []byte{
		0xFF, 0xD8, // SOI
		0x42, 0x43, 0x44, // non-marker data
	}

	var out bytes.Buffer
	s.ScrubFile("test.jpg", bytes.NewReader(jpeg), &out)

	result := out.Bytes()
	if !bytes.Contains(result, []byte{0x42, 0x43, 0x44}) {
		t.Error("non-marker data should be copied")
	}
}

func TestScrubFile_JPEG_TruncatedAPP(t *testing.T) {
	s := NewScrubber()
	// APP segment that's truncated (not enough data for length)
	jpeg := []byte{
		0xFF, 0xD8, // SOI
		0xFF, 0xE1, 0x00, // truncated - only 1 byte of length
	}

	var out bytes.Buffer
	s.ScrubFile("test.jpg", bytes.NewReader(jpeg), &out)
	// Should not panic
}

func TestScrubFile_JPEG_BadSegmentLength(t *testing.T) {
	s := NewScrubber()
	// APP segment with length larger than remaining data
	jpeg := []byte{
		0xFF, 0xD8, // SOI
		0xFF, 0xE1, 0x00, 0xFF, 0x00, 0x00, // length=255 but only 2 bytes of data
	}

	var out bytes.Buffer
	s.ScrubFile("test.jpg", bytes.NewReader(jpeg), &out)
}

func TestScrubFile_JPEG_SegmentLengthTooSmall(t *testing.T) {
	s := NewScrubber()
	// APP segment with length < 2
	jpeg := []byte{
		0xFF, 0xD8, // SOI
		0xFF, 0xE1, 0x00, 0x01, // length=1 (< 2, invalid)
	}

	var out bytes.Buffer
	s.ScrubFile("test.jpg", bytes.NewReader(jpeg), &out)
}

func TestScrubFile_JPEG_TruncatedNonAppSegment(t *testing.T) {
	s := NewScrubber()
	// Non-APP segment truncated
	jpeg := []byte{
		0xFF, 0xD8, // SOI
		0xFF, 0xDB, 0x00, // truncated DQT
	}

	var out bytes.Buffer
	s.ScrubFile("test.jpg", bytes.NewReader(jpeg), &out)
}

func TestScrubFile_JPEG_MalformedNonAppSegment(t *testing.T) {
	s := NewScrubber()
	// Non-APP segment with length exceeding data
	jpeg := []byte{
		0xFF, 0xD8, // SOI
		0xFF, 0xDB, 0x00, 0xFF, 0x00, // length=255 but only 1 byte
	}

	var out bytes.Buffer
	s.ScrubFile("test.jpg", bytes.NewReader(jpeg), &out)

	result := out.Bytes()
	// Should copy the malformed rest
	if len(result) < 2 {
		t.Error("should have at least SOI")
	}
}

func TestScrubFile_JPEG_MultipleAPPSegments(t *testing.T) {
	s := NewScrubber()
	jpeg := []byte{
		0xFF, 0xD8, // SOI
		0xFF, 0xE0, 0x00, 0x04, 0x00, 0x00, // APP0
		0xFF, 0xE1, 0x00, 0x04, 0x00, 0x00, // APP1
		0xFF, 0xDB, 0x00, 0x04, 0x00, 0x00, // DQT
		0xFF, 0xDA, 0x00, 0x02, // SOS
		0xFF, 0xD9, // EOI
	}

	var out bytes.Buffer
	s.ScrubFile("photo.jpg", bytes.NewReader(jpeg), &out)

	result := out.Bytes()
	// APP0 and APP1 should be stripped, DQT preserved
	if bytes.Contains(result, []byte{0xFF, 0xE0}) {
		t.Error("APP0 should be stripped")
	}
	if !bytes.Contains(result, []byte{0xFF, 0xDB}) {
		t.Error("DQT should be preserved")
	}
}

func TestScrubFile_PNG_StripMultipleMetadataChunks(t *testing.T) {
	s := NewScrubber()
	pngSig := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}

	ihdr := buildPNGChunk("IHDR", make([]byte, 13))
	text := buildPNGChunk("tEXt", []byte("Key\x00Value"))
	time := buildPNGChunk("tIME", make([]byte, 7))
	idat := buildPNGChunk("IDAT", []byte{0x00})
	iend := buildPNGChunk("IEND", nil)

	png := append(pngSig, ihdr...)
	png = append(png, text...)
	png = append(png, time...)
	png = append(png, idat...)
	png = append(png, iend...)

	var out bytes.Buffer
	s.ScrubFile("image.png", bytes.NewReader(png), &out)

	result := out.Bytes()
	if bytes.Contains(result, []byte("tEXt")) {
		t.Error("tEXt should be stripped")
	}
	if bytes.Contains(result, []byte("tIME")) {
		t.Error("tIME should be stripped")
	}
	if !bytes.Contains(result, []byte("IDAT")) {
		t.Error("IDAT should be preserved")
	}
}

func TestIsMetadataPresent_iTXt(t *testing.T) {
	s := NewScrubber()
	if !s.IsMetadataPresent([]byte("...iTXt...")) {
		t.Error("should detect iTXt")
	}
}

func TestIsMetadataPresent_eXIf(t *testing.T) {
	s := NewScrubber()
	if !s.IsMetadataPresent([]byte("...eXIf...")) {
		t.Error("should detect eXIf")
	}
}

func TestScrubFile_JPEG_CaseInsensitive(t *testing.T) {
	s := NewScrubber()
	data := []byte("not a jpeg")

	var out bytes.Buffer
	s.ScrubFile("Photo.JPG", bytes.NewReader(data), &out)
	// Should still try to process as JPEG (case-insensitive extension check)
	if !bytes.Equal(out.Bytes(), data) {
		t.Error("should pass through unchanged for invalid JPEG data")
	}
}

// buildPNGChunk builds a PNG chunk: [4-byte length][4-byte type][data][4-byte CRC]
func buildPNGChunk(chunkType string, data []byte) []byte {
	length := len(data)
	chunk := make([]byte, 0, 12+length)

	// Length (big-endian)
	chunk = append(chunk, byte(length>>24), byte(length>>16), byte(length>>8), byte(length))
	// Type
	chunk = append(chunk, []byte(chunkType)...)
	// Data
	chunk = append(chunk, data...)
	// CRC (fake - not validated in scrubber)
	chunk = append(chunk, 0x00, 0x00, 0x00, 0x00)

	return chunk
}
