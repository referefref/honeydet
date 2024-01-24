package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/TwiN/go-color"
	_ "github.com/mattn/go-sqlite3"
	"os"
)

func generateReport(results []DetectionResult, reportType string) {
	switch reportType {
	case "json":
		reportJSON(results)
	case "csv":
		reportCSV(results)
	default:
		if *debug {
			fmt.Println(color.Ize(color.Red, "[Debug] Invalid report type specified. No report generated."))
		}
	}
}

func reportJSON(results []DetectionResult) {
	data, err := json.Marshal(results)
	if err != nil {
		fmt.Println(color.Ize(color.Red, ("Error generating JSON report:" + err.Error())))
		return
	}
	fmt.Println(string(data))
}

func reportCSV(results []DetectionResult) {
	writer := csv.NewWriter(os.Stdout)
	defer writer.Flush()
	writer.Write([]string{"Host", "IsHoneypot", "HoneypotType"})

	for _, result := range results {
		record := []string{result.Host, fmt.Sprintf("%t", result.IsHoneypot), result.HoneypotType}
		writer.Write(record)
	}
}
