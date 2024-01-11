package main

import (
	"encoding/hex"
	"fmt"
	"github.com/TwiN/go-color"
	"github.com/gosnmp/gosnmp"
	"time"
)

func setupSNMPClient(host string, timeout int) (*gosnmp.GoSNMP, error) {

	timeoutDuration := time.Duration(timeout) * time.Second

	client := &gosnmp.GoSNMP{
		Target:    host,
		Port:      161,              // Default SNMP port
		Community: "public",         // Adjust as needed
		Version:   gosnmp.Version2c, // Adjust as needed
		Timeout:   timeoutDuration,  // Set timeout
		Retries:   1,                // Optional: Set retries
	}

	err := client.Connect()
	if err != nil {
		if *verbose {
			fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Verbose] Error connecting to SNMP server: %s", err)))
		}
		return nil, err
	}

	if *verbose {
		fmt.Println(color.Ize(color.Green, fmt.Sprintf("[Verbose] Successfully connected to SNMP server at %s", host)))
	}

	return client, nil
}

func sendSNMPRequest(client *gosnmp.GoSNMP, step Step) (string, error) {
	var pdu gosnmp.SnmpPDU
	switch step.InputType {
	case "string":
		pdu = gosnmp.SnmpPDU{Name: step.Input, Type: gosnmp.OctetString}
	case "hex":
		decodedInput, err := hex.DecodeString(step.Input)
		if err != nil {
			return "", err
		}
		pdu = gosnmp.SnmpPDU{Name: string(decodedInput), Type: gosnmp.OctetString}
	default:
		return "", fmt.Errorf("unsupported input type for SNMP: %s", step.InputType)
	}

	if *verbose {
		fmt.Println(color.Ize(color.Blue, fmt.Sprintf("[Verbose] Sending SNMP request: OID=%s", pdu.Name)))
	}

	response, err := client.Get([]string{pdu.Name})
	if err != nil {
		if *verbose {
			fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Verbose] SNMP request failed: %s", err)))
		}
		return "", err
	}

	if *verbose {
		fmt.Println(color.Ize(color.Green, "[Verbose] SNMP response received"))
	}

	var responseValue string
	if len(response.Variables) > 0 {
		variable := response.Variables[0]
		switch variable.Type {
		case gosnmp.OctetString:
			responseValue = string(variable.Value.([]byte))
		default:
			responseValue = fmt.Sprintf("%v", variable.Value)
		}

		if *verbose {
			fmt.Println(color.Ize(color.Cyan, fmt.Sprintf("[Verbose] SNMP response value: %s", responseValue)))
		}
	} else {
		if *verbose {
			fmt.Println(color.Ize(color.Yellow, "[Verbose] SNMP response contains no variables"))
		}
	}

	return responseValue, nil
}
