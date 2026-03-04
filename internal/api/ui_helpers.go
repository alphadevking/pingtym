package api

import (
	"fmt"
	"strings"
	"time"
)

// GenerateSparkline calculates the SVG points for a latency history [oldest...newest]
func GenerateSparkline(latencies []int, maxLat int, width, height int) string {
	if len(latencies) == 0 || maxLat == 0 {
		return ""
	}

	// For a consistent width, we always act as if we have 20 slots.
	// Data starts from the left (index 0).
	points := []string{}
	stepX := width / 19 // 20 slots = 19 gaps
	
	for i, val := range latencies {
		if i >= 20 { break }
		if val < 0 { continue }
		
		x := i * stepX
		ratio := float64(val) / float64(maxLat)
		if ratio > 1.0 { ratio = 1.0 }
		y := float64(height) - (ratio * float64(height) * 0.8)
		
		points = append(points, fmt.Sprintf("%d,%.1f", x, y))
	}
	
	return strings.Join(points, " ")
}

// FormatLatency returns a human-readable latency string
func FormatLatency(d time.Duration) string {
	if d == 0 {
		return "N/A"
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}

// GetTemplateFuncs returns the map of functions used in HTML templates
func GetTemplateFuncs() map[string]interface{} {
	return map[string]interface{}{
		"until": func(n int) []int {
			res := make([]int, n)
			for i := range res {
				res[i] = i
			}
			return res
		},
		"multiply":   func(a, b int) int { return a * b },
		"divide":     func(a, b int) int { if b == 0 { return a }; return a / b },
		"minus":      func(a, b int) int { return a - b },
		"sparkPoints": GenerateSparkline,
		"formatLat":   FormatLatency,
		"padHistory": func(history []int, size int) []int {
			// Pad at the END so data starts from the left
			res := make([]int, size)
			for i := range res {
				res[i] = -1
			}
			copy(res, history)
			return res
		},
	}
}
