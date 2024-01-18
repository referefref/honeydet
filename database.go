package main

import (
	"database/sql"
	"fmt"
	"github.com/TwiN/go-color"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"net/http"
	"time"
)

func initializeDatabase() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "./scans.db")
	if err != nil {
		return nil, err
	}

	createScansTableSQL := `
    CREATE TABLE IF NOT EXISTS scans (
        scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
        start_time DATETIME,
        end_time DATETIME,
        parameters TEXT
    );`
	_, err = db.Exec(createScansTableSQL)
	if err != nil {
		return nil, err
	}

	createScanResultsTableSQL := `
    CREATE TABLE IF NOT EXISTS scan_results (
        result_id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER,
        host TEXT,
        port INTEGER,
        is_honeypot BOOLEAN,
        honeypot_type TEXT,
        detection_time DATETIME,
	comment TEXT,
	confidence TEXT,
	FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
    );`
	_, err = db.Exec(createScanResultsTableSQL)
	if err != nil {
		return nil, err
	}

	return db, nil
}

func insertScanResults(db *sql.DB, scanID int64, results []DetectionResult) error {
	stmt, err := db.Prepare("INSERT INTO scan_results(scan_id, host, port, is_honeypot, honeypot_type, confidence, comment, detection_time) VALUES(?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, result := range results {
		if *verbose {
			log.Printf(color.Ize(color.Cyan, fmt.Sprintf("[Verbose] Inserting result into database: ScanID=%d, Host=%s, Port=%d, IsHoneypot=%t, HoneypotType=%s, Confidence=%s, Comment=%s, DetectionTime=%s", scanID, result.Host, result.Port, result.IsHoneypot, result.HoneypotType, result.Confidence, result.Comment, result.DetectionTime)))

		}
		_, err := stmt.Exec(scanID, result.Host, result.Port, result.IsHoneypot, result.HoneypotType, result.Confidence, result.Comment, result.DetectionTime)
		if err != nil {
			return err
		}
	}

	return nil
}

func insertScanData(db *sql.DB, startTime time.Time, parameters string) (int64, error) {
	stmt, err := db.Prepare("INSERT INTO scans(start_time, parameters) VALUES(?, ?)")
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	res, err := stmt.Exec(startTime, parameters)
	if err != nil {
		return 0, err
	}

	scanID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}

	return scanID, nil
}

func updateScanStatus(db *sql.DB, scanID int64, endTime time.Time) error {
	stmt, err := db.Prepare("UPDATE scans SET end_time = ? WHERE scan_id = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(endTime, scanID)
	return err
}

func clearDatabaseHandler(w http.ResponseWriter, r *http.Request) {
	db, err := initializeDatabase()
	if err != nil {
		log.Printf("Error initializing database: %s", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	_, err = db.Exec("DELETE FROM scan_results")
	if err != nil {
		log.Printf("Error clearing scan_results table: %s", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("DELETE FROM scans")
	if err != nil {
		log.Printf("Error clearing scans table: %s", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, "Database cleared successfully")
}

func deleteScanHandler(w http.ResponseWriter, r *http.Request) {
	db, err := initializeDatabase()
	if err != nil {
		log.Printf("Error initializing database: %s", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer db.Close()

	scanId := r.URL.Query().Get("scanId")
	if scanId == "" {
		http.Error(w, "Scan ID is required", http.StatusBadRequest)
		return
	}

	_, err = db.Exec("DELETE FROM scan_results WHERE scan_id = ?", scanId)
	if err != nil {
		log.Printf("Error deleting from scan_results table: %s", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("DELETE FROM scans WHERE scan_id = ?", scanId)
	if err != nil {
		log.Printf("Error deleting from scans table: %s", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "Scan with ID %s deleted successfully", scanId)
}
