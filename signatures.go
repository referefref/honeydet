package main

import (
	"fmt"
	"github.com/TwiN/go-color"
	_ "github.com/mattn/go-sqlite3"
	"gopkg.in/yaml.v2"
	"os"
)

func readSignatures(filePath string) (Signatures, error) {
	var signatures Signatures

	if *verbose {
		fmt.Println(color.Ize(color.White, fmt.Sprintf("[Verbose] Reading signatures from file: %s", filePath)))
	}

	file, err := os.ReadFile(filePath)
	if err != nil {
		if *verbose {
			fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Verbose] Error reading signature file: %s", err)))
		}
		return signatures, err
	}

	err = yaml.Unmarshal(file, &signatures)
	if err != nil {
		if *verbose {
			fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Verbose] Error parsing YAML file: %s", err)))
			if *debug {
				if yamlError, ok := err.(*yaml.TypeError); ok {
					fmt.Println(color.Ize(color.Red, fmt.Sprintf("[Debug] YAML Type Error: %s", yamlError.Errors)))
				}
			}
		}
	}
	validSignatures := make([]HoneypotSignature, 0)
	for _, signature := range signatures.Signatures {
		if signature.ID == "" || signature.Name == "" || signature.Port == "" || signature.Proto == "" || len(signature.Steps) == 0 {
			if *debug {
				fmt.Println(color.Ize(color.Yellow, fmt.Sprintf("[Debug] Incomplete or invalid signature detected (ID: %s). Skipping.", signature.ID)))
			}
			continue
		}
		validSignatures = append(validSignatures, signature)
	}
	signatures.Signatures = validSignatures

	if *verbose {
		for _, signature := range validSignatures {
			if *debug {
				fmt.Println(color.Ize(color.Cyan, fmt.Sprintf("[Debug] Loaded signature: Name=%s, Port=%s, Proto=%s, Steps=%d, Confidence=%s, Comment=%s",
					signature.Name, signature.Port, signature.Proto, len(signature.Steps), signature.Confidence, signature.Comment)))
			}
			for _, step := range signature.Steps {
				if *debug {
					fmt.Println(color.Ize(color.Cyan, fmt.Sprintf("[Debug] Step: InputType=%s, OutputMatchType=%s", step.InputType, step.OutputMatchType)))
				}
			}
		}
		fmt.Println(color.Ize(color.White, fmt.Sprintf("[Verbose] Total loaded signatures: %d", len(signatures.Signatures))))
	}

	return signatures, nil
}
