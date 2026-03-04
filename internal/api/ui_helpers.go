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

	// Precision Fix: Use float64 for steps to ensure the sparkline reaches the right edge perfectly
	points := []string{}
	stepX := float64(width) / 19.0 // 20 slots = 19 gaps

	for i, val := range latencies {
		if i >= 20 {
			break
		}
		if val <= 0 {
			continue
		} // 0 = monitor was down, skip to show a visible gap

		x := float64(i) * stepX
		ratio := float64(val) / float64(maxLat)
		if ratio > 1.0 {
			ratio = 1.0
		}
		y := float64(height) - (ratio * float64(height) * 0.8)

		// Use %.1f for cleaner SVG paths without losing precision
		points = append(points, fmt.Sprintf("%.1f,%.1f", x, y))
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
		"multiply": func(a, b int64) int64 { return a * b },
		"divide": func(a, b int64) int64 {
			if b == 0 {
				return a
			}
			return a / b
		},
		"minus":       func(a, b int64) int64 { return a - b },
		"sparkPoints": GenerateSparkline,
		"formatLat":   FormatLatency,
		"padHistory": func(history []int, size int) []int {
			res := make([]int, size)
			for i := range res {
				res[i] = -1
			}
			copy(res, history)
			return res
		},
	}
}
