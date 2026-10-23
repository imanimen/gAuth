package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/imanimen/gAuth/services"
)

// filePathCache stores resolved file service URLs. It is capped to keep the
// memory footprint bounded; when the cap is reached the whole cache is
// dropped which is acceptable for a short lived service.
const filePathCacheLimit = 4096

var (
	filePathCacheMu sync.RWMutex
	filePathCache   = make(map[string]string)
)

// GetFilePath retrieves the public URL for the given file ID from the file
// service API and caches the result.
func GetFilePath(fileID string) (string, error) {
	if fileID == "" {
		return "", nil
	}

	filePathCacheMu.RLock()
	url, ok := filePathCache[fileID]
	filePathCacheMu.RUnlock()
	if ok {
		return url, nil
	}

	payload, err := json.Marshal(map[string]string{"file_id": fileID})
	if err != nil {
		return "", err
	}

	apiCall, err := services.Call(services.GetEnv("FILE_SERVICE_URL", "")+"/find", "POST", payload)
	if err != nil {
		return "", err
	}

	filePath, ok := apiCall["file_path"].(string)
	if !ok || filePath == "" {
		return "", errors.New("file path not found in response")
	}

	cdnURL := services.GetEnv("CDN_URL", "")
	if cdnURL != "" {
		filePath = fmt.Sprintf("%s/%s", cdnURL, filePath)
	}

	filePathCacheMu.Lock()
	if len(filePathCache) >= filePathCacheLimit {
		filePathCache = make(map[string]string)
	}
	filePathCache[fileID] = filePath
	filePathCacheMu.Unlock()

	return filePath, nil
}

// CalculateAge returns the age in full years reached by a person with the
// given birth date as of today.
func CalculateAge(birthDate time.Time) int {
	currentDate := time.Now()

	age := currentDate.Year() - birthDate.Year()
	beforeBirthday :=
		currentDate.Month() < birthDate.Month() ||
			(currentDate.Month() == birthDate.Month() && currentDate.Day() < birthDate.Day())
	if beforeBirthday {
		age--
	}

	return age
}
