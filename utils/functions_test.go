package utils

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCalculateAge(t *testing.T) {
	today := time.Now()

	tests := []struct {
		name      string
		birthDate time.Time
	}{
		{"born today", today.AddDate(0, 0, 0)},
		{"birthday today", today.AddDate(-30, 0, 0)},
		{"birthday passed this year", today.AddDate(-30, 0, -1)},
		{"birthday not yet this year", today.AddDate(-30, 0, 1)},
		{"one year old", today.AddDate(-1, 0, 0)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			expected := today.Year() - tc.birthDate.Year()
			if today.Month() < tc.birthDate.Month() ||
				(today.Month() == tc.birthDate.Month() && today.Day() < tc.birthDate.Day()) {
				expected--
			}
			assert.Equal(t, expected, CalculateAge(tc.birthDate))
		})
	}
}

func TestCalculateAgeKnownDates(t *testing.T) {
	today := time.Now()

	assert.Equal(t, 30, CalculateAge(today.AddDate(-30, 0, 0)), "birthday is today")
	assert.Equal(t, 30, CalculateAge(today.AddDate(-30, 0, -1)), "birthday already passed")
	assert.Equal(t, 29, CalculateAge(today.AddDate(-30, 0, 1)), "birthday later this year")
	assert.Equal(t, 1, CalculateAge(today.AddDate(-1, 0, 0)))
}

func TestGetFilePathCachesResolution(t *testing.T) {
	var hits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		fmt.Fprint(w, `{"file_path":"avatars/42.png"}`)
	}))
	defer server.Close()
	t.Setenv("FILE_SERVICE_URL", server.URL)
	t.Setenv("CDN_URL", "https://cdn.example.com")

	url, err := GetFilePath("file-1")
	require.NoError(t, err)
	assert.Equal(t, "https://cdn.example.com/avatars/42.png", url)

	// second call must come from cache
	url, err = GetFilePath("file-1")
	require.NoError(t, err)
	assert.Equal(t, "https://cdn.example.com/avatars/42.png", url)
	assert.Equal(t, 1, hits)
}

func TestGetFilePathEmptyID(t *testing.T) {
	url, err := GetFilePath("")
	require.NoError(t, err)
	assert.Empty(t, url)
}

func TestGetFilePathMissingKeyInResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"nope":"nothing"}`)
	}))
	defer server.Close()
	t.Setenv("FILE_SERVICE_URL", server.URL)

	_, err := GetFilePath("file-x")
	assert.ErrorContains(t, err, "file path not found")
}
