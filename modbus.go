package main

import (
	"fmt"
	"github.com/TwiN/go-color"
	"github.com/simonvetter/modbus"
	"time"
)

func setupModbusClient(host string, port int, timeout time.Duration) (*modbus.ModbusClient, error) {
	client, err := modbus.NewClient(&modbus.ClientConfiguration{
		URL:     fmt.Sprintf("tcp://%s:%d", host, port),
		Timeout: timeout,
	})
	if err != nil {
		if *verbose {
			fmt.Printf(color.Ize(color.Red, "[Verbose] Error creating Modbus client: %s\n"), err)
		}
		return nil, err
	}

	err = client.Open()
	if err != nil {
		if *verbose {
			fmt.Printf(color.Ize(color.Red, "[Verbose] Error opening Modbus connection: %s\n"), err)
		}
		return nil, err
	}

	if *verbose {
		fmt.Printf(color.Ize(color.Green, "[Verbose] Successfully connected to Modbus server at %s:%d\n"), host, port)
	}

	return client, nil
}

func sendModbusRequest(client *modbus.ModbusClient, step Step) (string, error) {
	var response string

	if step.InputType == "hex" {
		address, err := hexStringToUint16(step.Input)
		if err != nil {
			return "", err
		}

		var value uint16
		value, err = client.ReadRegister(address, modbus.HOLDING_REGISTER)
		if err != nil {
			if *verbose {
				fmt.Printf(color.Ize(color.Red, "[Verbose] Error reading Modbus register: %s\n"), err)
			}
			return "", err
		}

		response = fmt.Sprintf("%v", value)
	} else {
	}

	if *verbose {
		fmt.Printf(color.Ize(color.Green, "[Verbose] Modbus response: %s\n"), response)
	}

	return response, nil
}

func hexStringToUint16(hexStr string) (uint16, error) {
	var value uint16
	_, err := fmt.Sscanf(hexStr, "%x", &value)
	if err != nil {
		return 0, err
	}
	return value, nil
}
