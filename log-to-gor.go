package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"time"

	parser "github.com/nekrassov01/access-log-parser"
)

// The delimiter used by goreplay to separate payloads.
const gorPayloadDelimiter = "🐵🙈🙉"

// CombinedLogFormat is the standard format string for Apache Combined Log files.
const CombinedLogFormat = `%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"`

func main() {
	// 1. Check for command-line arguments
	if len(os.Args) != 3 {
		fmt.Println("Usage: log-to-gor <input_logfile> <output_gorfile>")
		fmt.Println("Example: ./log-to-gor access.log requests.gor")
		os.Exit(1)
	}

	inputFile := os.Args[1]
	outputFile := os.Args[2]

	log.Printf("Starting conversion from %s to %s", inputFile, outputFile)

	// 2. Open the input log file for reading
	in, err := os.Open(inputFile)
	if err != nil {
		log.Fatalf("Error opening input file %s: %v", inputFile, err)
	}
	defer in.Close()

	// 3. Create the output .gor file for writing
	out, err := os.Create(outputFile)
	if err != nil {
		log.Fatalf("Error creating output file %s: %v", outputFile, err)
	}
	defer out.Close()

	// 4. Initialize the log parser for Apache Combined Log Format
	ctx := context.Background()
	parserInstance := parser.NewApacheCLFRegexParser(ctx, io.Discard, parser.Option{})

	// 5. Process the files line by line
	count, err := processLogs(in, out, parserInstance)
	if err != nil {
		log.Fatalf("Error during processing: %v", err)
	}

	log.Printf("✅ Success! Converted %d log entries.", count)
	log.Printf("Output saved to %s", outputFile)
}

// processLogs reads from the reader, parses logs, and writes to the writer in .gor format.
func processLogs(r io.Reader, w io.Writer, p *parser.RegexParser) (int, error) {
	scanner := bufio.NewScanner(r)
	processedCount := 0
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		// Parse the log line
		entry, err := p.ParseString(line)
		if err != nil || len(entry.Errors) > 0 || entry.Matched == 0 {
			log.Printf("⚠️  Skipping malformed line: %s (%v)", line, err)
			continue
		}
		// Extract timestamp and request line
		// Find the request line in the log
		// For Combined Log Format, request line is in quotes after the date
		// We'll use regex to extract it
		var requestLine string
		var timestamp int64
		// Try to extract request line and timestamp from the parsed result
		// The parser does not expose fields directly, so we use regex fallback
		re := regexp.MustCompile(`"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) ([^ ]+) ([^"]+)"`)
		matches := re.FindStringSubmatch(line)
		if len(matches) == 4 {
			requestLine = fmt.Sprintf("%s %s %s", matches[1], matches[2], matches[3])
		} else {
			continue
		}
		// Extract timestamp from the log line
		timeRe := regexp.MustCompile(`\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}) [^\]]+\]`)
		timeMatch := timeRe.FindStringSubmatch(line)
		if len(timeMatch) == 2 {
			t, err := time.Parse("02/Jan/2006:15:04:05", timeMatch[1])
			if err == nil {
				timestamp = t.UnixNano()
			}
		}
		// Generate request ID
		reqID, err := generateRequestID()
		if err != nil {
			log.Printf("⚠️  Skipping line due to ID generation error: %v", err)
			continue
		}
		// Write .gor format
		reqType := "1"
		latency := 0
		_, err = fmt.Fprintf(w, "%s %s %d %d\n", reqType, reqID, timestamp, latency)
		if err != nil {
			return processedCount, fmt.Errorf("failed to write header: %w", err)
		}
		_, err = fmt.Fprintf(w, "%s\r\n\r\n\n", requestLine)
		if err != nil {
			return processedCount, fmt.Errorf("failed to write request line: %w", err)
		}
		_, err = fmt.Fprintf(w, "%s\n", gorPayloadDelimiter)
		if err != nil {
			return processedCount, fmt.Errorf("failed to write delimiter: %w", err)
		}
		processedCount++
	}
	if err := scanner.Err(); err != nil {
		return processedCount, fmt.Errorf("error reading input file: %w", err)
	}
	return processedCount, nil
}

// generateRequestID creates a random 16-byte slice and returns it as a 32-character hex string.
func generateRequestID() (string, error) {
	bytes := make([]byte, 12)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
