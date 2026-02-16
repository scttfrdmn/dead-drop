package metadata

import (
	"bytes"
	"fmt"
	"io"
	"strings"
)

// Scrubber handles metadata removal from files
type Scrubber struct{}

// NewScrubber creates a new metadata scrubber
func NewScrubber() *Scrubber {
	return &Scrubber{}
}

// ScrubFile removes metadata from common file types
func (s *Scrubber) ScrubFile(filename string, reader io.Reader, writer io.Writer) error {
	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Detect file type and apply appropriate scrubbing
	cleaned := data
	lower := strings.ToLower(filename)

	if strings.HasSuffix(lower, ".jpg") || strings.HasSuffix(lower, ".jpeg") {
		cleaned = s.stripJPEGExif(data)
	} else if strings.HasSuffix(lower, ".png") {
		cleaned = s.stripPNGMetadata(data)
	}
	// Add more file types as needed

	if _, err := writer.Write(cleaned); err != nil {
		return fmt.Errorf("failed to write cleaned file: %w", err)
	}

	return nil
}

// stripJPEGExif removes EXIF data from JPEG files
func (s *Scrubber) stripJPEGExif(data []byte) []byte {
	// JPEG structure: FFD8 (SOI) + segments + FFD9 (EOI)
	// APP1 segment (FFE1) typically contains EXIF data

	if len(data) < 4 || data[0] != 0xFF || data[1] != 0xD8 {
		// Not a valid JPEG, return as-is
		return data
	}

	result := bytes.NewBuffer(nil)
	result.Write(data[0:2]) // Write SOI marker (FFD8)

	i := 2
	for i < len(data)-1 {
		// Check for marker
		if data[i] != 0xFF {
			// Not a marker, skip to end
			result.Write(data[i:])
			break
		}

		marker := data[i+1]

		// If we hit compressed data (SOS marker), copy rest and break
		if marker == 0xDA {
			result.Write(data[i:])
			break
		}

		// Skip APP0-APP15 markers (FFE0-FFEF) which contain metadata
		if marker >= 0xE0 && marker <= 0xEF {
			// Read segment length
			if i+3 >= len(data) {
				break
			}
			segmentLen := int(data[i+2])<<8 | int(data[i+3])
			// Skip this segment (marker + length + data)
			i += 2 + segmentLen
			continue
		}

		// Copy other segments
		if i+3 >= len(data) {
			break
		}
		segmentLen := int(data[i+2])<<8 | int(data[i+3])
		if i+2+segmentLen > len(data) {
			// Malformed, copy rest
			result.Write(data[i:])
			break
		}
		result.Write(data[i : i+2+segmentLen])
		i += 2 + segmentLen
	}

	return result.Bytes()
}

// stripPNGMetadata removes metadata chunks from PNG files
func (s *Scrubber) stripPNGMetadata(data []byte) []byte {
	// PNG structure: signature + chunks
	// Chunks to remove: tEXt, zTXt, iTXt, tIME, pHYs, etc.

	pngSignature := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	if len(data) < 8 || !bytes.Equal(data[0:8], pngSignature) {
		// Not a valid PNG, return as-is
		return data
	}

	result := bytes.NewBuffer(nil)
	result.Write(pngSignature)

	// Metadata chunk types to strip
	stripChunks := map[string]bool{
		"tEXt": true, // Textual data
		"zTXt": true, // Compressed text
		"iTXt": true, // International text
		"tIME": true, // Last modification time
		"pHYs": true, // Physical pixel dimensions
		"sPLT": true, // Suggested palette
		"eXIf": true, // EXIF data
	}

	i := 8
	for i < len(data) {
		if i+8 > len(data) {
			break
		}

		// Read chunk length
		chunkLen := int(data[i])<<24 | int(data[i+1])<<16 | int(data[i+2])<<8 | int(data[i+3])
		chunkType := string(data[i+4 : i+8])

		totalChunkSize := 12 + chunkLen // length(4) + type(4) + data(n) + crc(4)
		if i+totalChunkSize > len(data) {
			break
		}

		// Keep essential chunks, strip metadata
		if !stripChunks[chunkType] {
			result.Write(data[i : i+totalChunkSize])
		}

		i += totalChunkSize

		// IEND is the last chunk
		if chunkType == "IEND" {
			break
		}
	}

	return result.Bytes()
}

// IsMetadataPresent checks if common metadata markers exist
func (s *Scrubber) IsMetadataPresent(data []byte) bool {
	// Check for EXIF in JPEG
	if bytes.Contains(data, []byte("Exif")) {
		return true
	}

	// Check for GPS data
	if bytes.Contains(data, []byte("GPS")) {
		return true
	}

	// Check for PNG text chunks
	if bytes.Contains(data, []byte("tEXt")) ||
	   bytes.Contains(data, []byte("iTXt")) ||
	   bytes.Contains(data, []byte("eXIf")) {
		return true
	}

	return false
}
