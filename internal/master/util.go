// util.go provides shared HTTP helpers (CORS headers, JSON writer, error
// responder) and ID generators used across the master REST and MCP handlers.
package master

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
)

// SetCorsHeaders sets HTTP CORS headers to allow cross-origin requests from any origin.
//
// Adds the following CORS headers to the response:
//   - Access-Control-Allow-Origin: * (allow all origins)
//   - Access-Control-Allow-Methods: GET, PATCH, POST, PUT, DELETE, OPTIONS
//   - Access-Control-Allow-Headers: Content-Type, Authorization, X-API-Key, Cache-Control
//
// This enables browser-based clients to make cross-origin requests to the API.
func SetCorsHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, PATCH, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, Cache-Control")
}

// HTTPError writes an HTTP error response with the given message and status code.
//
// Sets CORS headers and Content-Type to application/json, then writes the status code.
// The error message is encoded as a JSON object with an "error" key, for example:
// {"error": "Invalid request body"}. This ensures consistent error formatting across
// all API endpoints.
//
// Parameters:
//   - w: The HTTP response writer
//   - message: Human-readable error message
//   - statusCode: HTTP status code (e.g., 400, 401, 404, 500)
func HTTPError(w http.ResponseWriter, message string, statusCode int) {
	SetCorsHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// WriteJSON writes data as JSON response with the given status code and CORS headers.
//
// Sets CORS headers and Content-Type to application/json, writes the status code,
// and encodes the provided data as JSON. This is the standard response writer for
// successful API operations returning structured data (instances, info, etc.).
// The data can be any type that json.Encoder can marshal (structs, slices, maps).
//
// Parameters:
//   - w: The HTTP response writer
//   - statusCode: HTTP status code (e.g., 200, 201, 204)
//   - data: The data structure to encode as JSON
func WriteJSON(w http.ResponseWriter, statusCode int, data any) {
	SetCorsHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

// GenerateID generates a random 8-character hexadecimal ID for instances.
//
// Reads 4 random bytes from crypto/rand and encodes them as hexadecimal,
// producing an 8-character alphanumeric string. Used to generate unique
// identifiers for new instances when they are created via the API.
func GenerateID() string {
	bytes := make([]byte, 4)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// GenerateMID generates a random 16-character hexadecimal Master ID.
//
// Reads 8 random bytes from crypto/rand and encodes them as hexadecimal,
// producing a 16-character alphanumeric string. The Master ID uniquely identifies
// a nodepass master instance across the network and is persisted in the state file.
func GenerateMID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// GenerateAPIKey generates a random 32-character hexadecimal API key for authentication.
//
// Reads 16 random bytes from crypto/rand and encodes them as hexadecimal,
// producing a 32-character alphanumeric string. This API key is used in the
// X-API-Key HTTP header to authenticate requests to protected endpoints.
// The key is persisted in the master's instance registry for crash recovery.
func GenerateAPIKey() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
