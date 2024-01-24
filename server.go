package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/TwiN/go-color"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"
)

func getScans(db *sql.DB) ([]map[string]interface{}, error) {
	rows, err := db.Query(`
        SELECT s.scan_id, s.start_time, s.end_time, s.parameters,
               r.result_id, r.host, r.port, r.is_honeypot, r.honeypot_type, r.confidence, r.comment, r.detection_time, r.shodan_info
        FROM scans s
        LEFT JOIN scan_results r ON s.scan_id = r.scan_id
        ORDER BY s.scan_id, r.result_id
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans = make(map[int64]map[string]interface{})
	for rows.Next() {
		var scanID int64
		var startTime, endTime, detectionTime sql.NullString
		var resultID sql.NullInt64
		var host sql.NullString
		var port sql.NullInt64
		var parameters string
		var isHoneypot sql.NullBool
		var honeypotType sql.NullString
		var confidence sql.NullString
		var comment sql.NullString
		var shodanInfoJSON sql.NullString

		err = rows.Scan(&scanID, &startTime, &endTime, &parameters, &resultID, &host, &port, &isHoneypot, &honeypotType, &confidence, &comment, &detectionTime, &shodanInfoJSON)
		if err != nil {
			return nil, err
		}

		scan, exists := scans[scanID]
		if !exists {
			scan = make(map[string]interface{})
			scan["scan_id"] = scanID
			scan["start_time"] = startTime.String
			scan["end_time"] = endTime.String
			scan["results"] = make([]map[string]interface{}, 0)
			scan["target_hosts"] = extractHostsFromParameters(parameters)
			scan["target_ports"] = extractPortsFromParameters(parameters)
		}

		if host.Valid && port.Valid {
			result := map[string]interface{}{
				"result_id":      resultID.Int64,
				"host":           host.String,
				"port":           int(port.Int64),
				"is_honeypot":    isHoneypot.Bool,
				"honeypot_type":  honeypotType.String,
				"confidence":     confidence.String,
				"comment":        comment.String,
				"detection_time": detectionTime.String,
				"shodan_info":    shodanInfoJSON.String, // Use the String field for Shodan info
			}
			scan["results"] = append(scan["results"].([]map[string]interface{}), result)
		}

		scans[scanID] = scan
	}

	var scanSlice []map[string]interface{}
	for _, scan := range scans {
		scanSlice = append(scanSlice, scan)
	}

	return scanSlice, nil
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
	db, err := initializeDatabase()
	if err != nil {
		log.Printf(color.Ize(color.Red, fmt.Sprintf("Error initializing database: %s", err)))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	if *verbose {
		log.Printf(color.Ize(color.White, "Received request: "+r.URL.String()))
	}

	checkPing, _ := strconv.ParseBool(r.URL.Query().Get("checkPing"))
	bypassPortCheck, _ := strconv.ParseBool(r.URL.Query().Get("bypassPortCheck"))
	threads, err := strconv.Atoi(r.URL.Query().Get("threads"))
	if err != nil || threads <= 0 {
		threads = 1
	}

	hosts, err := parseHostInput(r.URL.Query().Get("host"))
	if err != nil {
		log.Printf(color.Ize(color.Red, "Error parsing host input: "+err.Error()))
		return
	}

	ports, err := parsePortInput(r.URL.Query().Get("port"))
	if err != nil {
		log.Printf(color.Ize(color.Red, "Error parsing port input: "+err.Error()))
		return
	}

	proto := r.URL.Query().Get("proto")
	timeout, _ := strconv.Atoi(r.URL.Query().Get("timeout"))
	if timeout == 0 {
		timeout = 5
	}

	signatures, err := readSignatures(*signatureFile)
	if err != nil {
		log.Printf(color.Ize(color.Red, "Error reading signatures: "+err.Error()))
		return
	}

	var responsiveHosts []string
	if checkPing {
		log.Printf(color.Ize(color.Blue, "Ping check enabled. Starting to ping hosts."))
		var pingWg sync.WaitGroup
		for _, host := range hosts {
			pingWg.Add(1)
			go func(h string) {
				defer pingWg.Done()
				log.Printf(color.Ize(color.Blue, "Pinging host: "+h))
				if hostRespondsToPing(h, timeout) {
					responsiveHosts = append(responsiveHosts, h)
					if *verbose {
						log.Printf(color.Ize(color.Green, "Host "+h+" responds to ping"))
					}
				} else {
					log.Printf(color.Ize(color.Yellow, "No response from host: "+h))
				}
			}(host)
		}
		pingWg.Wait()
		log.Printf(color.Ize(color.Blue, "Ping check completed."))
	} else {
		responsiveHosts = hosts
	}

	totalWorkUnits := len(responsiveHosts) * len(ports)
	workUnitsPerThread := totalWorkUnits / threads
	if totalWorkUnits%threads != 0 {
		workUnitsPerThread++
	}

	var scanWg sync.WaitGroup
	resultsChan := make(chan []DetectionResult, threads)

	for i := 0; i < threads; i++ {
		scanWg.Add(1)
		go func(threadID int) {
			defer scanWg.Done()
			var combinedResults []DetectionResult
			for j := threadID; j < totalWorkUnits; j += threads {
				hostIndex := j / len(ports)
				portIndex := j % len(ports)
				if hostIndex < len(responsiveHosts) {
					host := responsiveHosts[hostIndex]
					port := ports[portIndex]
					if *verbose {
						log.Printf(color.Ize(color.Blue, "Processing host: "+host+" on port "+strconv.Itoa(port)))
					}
					results := detectHoneypot(host, []int{port}, proto, signatures, timeout, bypassPortCheck, shodanClient)
					combinedResults = append(combinedResults, results...)
				}
			}
			resultsChan <- combinedResults
		}(i)
	}

	scanWg.Wait()
	close(resultsChan)

	var finalResults []DetectionResult
	for results := range resultsChan {
		finalResults = append(finalResults, results...)
	}

	startTime := time.Now()
	scanParameters := r.URL.String()
	scanID, err := insertScanData(db, startTime, scanParameters)
	if err != nil {
		log.Printf(color.Ize(color.Red, "Error inserting scan data: "+err.Error()))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	err = insertScanResults(db, scanID, finalResults)
	if err != nil {
		log.Printf(color.Ize(color.Red, "Error inserting scan results: "+err.Error()))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	endTime := time.Now()
	err = updateScanStatus(db, scanID, endTime)
	if err != nil {
		log.Printf(color.Ize(color.Red, "Error updating scan status: "+err.Error()))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(finalResults)
}
