package api

import (
	"fmt"
	"strings"
	"time"
)

// GenerateSparkline calculates the SVG points for a latency history
func GenerateSparkline(latencies []int, maxLat int, width, height int) string {
	if len(latencies) == 0 || maxLat == 0 {
		return ""
	}

	points := []string{}
	stepX := width / 20 // Fixed for 20 points
	
	for i, val := range latencies {
		if val <= 0 {
			continue
		}
		
		x := i * stepX
		// Scale Y to 80% of height to keep it in view
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
	}
}
