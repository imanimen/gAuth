package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/imanimen/gAuth/services"
)

// getFilePath retrieves the file path for the given file ID from the
// file service API. It caches the result to avoid unnecessary API calls.
// TODO: cache for development
var filePathCache = make(map[string]string)

// getFilePath retrieves the file path for the given file ID from the
// file service API. It caches the result to avoid unnecessary API calls.
func GetFilePath(fileId string) (string, error) {

	// Check if the file path is already cached
	if cachedPath, exists := filePathCache[fileId]; exists {
		return cachedPath, nil
	}

	payloadData := map[string]string{
		"file_id": fileId,
	}

	payloadBytes, err := json.Marshal(payloadData)
	if err != nil {
		fmt.Println("Error marshaling payload:", err)
		return "", err
	}

	apiCall, err := services.Call(os.Getenv("FILE_SERVICE_URL")+"/find", "POST", payloadBytes)
	if err != nil {
		fmt.Println("Error calling file service:", err)
		return "", err
	}

	filePath, ok := apiCall["file_path"].(string)
	if !ok {
		fmt.Println("File path not found in response")
		return "", err
	}

	filePathCache[fileId] = os.Getenv("CDN_URL") + "/" + filePath

	return filePathCache[fileId], nil
}

// CalculateAge calculates the age of a person given their birth date.
// It takes a time.Time representing the birth date and returns the
// person's age as an integer.
func CalculateAge(birthDate time.Time) int {
	currentDate := time.Now()
	age := currentDate.Year() - birthDate.Year()

	// Check if the birthdate has occurred this year already
	if currentDate.YearDay() < birthDate.YearDay() {
		age--
	}

	return age
}
