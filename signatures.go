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
		fmt.Println(color.Ize(color.Blue, fmt.Sprintf("[Verbose] Reading signatures from file: %s", filePath)))
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
		}
		return signatures, err
	}

	if *verbose {
		fmt.Println(color.Ize(color.Green, "[Verbose] YAML signatures loaded successfully"))
		for _, signature := range signatures.Signatures {
			fmt.Println(color.Ize(color.Cyan, fmt.Sprintf("[Verbose] Loaded signature: Name=%s, Port=%s, Proto=%s, Steps=%d, Confidence=%s, Comment=%s, InputType=%s",
				signature.Name, signature.Port, signature.Proto, len(signature.Steps), signature.Confidence, signature.Comment, signature.Steps[0].InputType)))
		}
		fmt.Println(color.Ize(color.Green, fmt.Sprintf("[Verbose] Total loaded signatures: %d", len(signatures.Signatures))))
	}

	return signatures, nil
}
