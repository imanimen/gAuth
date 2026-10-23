package providers

import "net/http"

import "github.com/gin-gonic/gin"

// Envelope is the standard response shape returned by every endpoint.
type Envelope struct {
	Version string      `json:"version"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

func respond(c *gin.Context, status int, data interface{}, err string) {
	c.JSON(status, Envelope{
		Version: apiVersionFromContext(c),
		Data:    data,
		Error:   err,
	})
}

// RespondOK writes a standard success envelope.
func RespondOK(c *gin.Context, data interface{}) {
	respond(c, http.StatusOK, data, "")
}

// RespondCreated writes a standard created envelope.
func RespondCreated(c *gin.Context, data interface{}) {
	respond(c, http.StatusCreated, data, "")
}

// RespondError writes a standard error envelope.
func RespondError(c *gin.Context, status int, message string) {
	respond(c, status, nil, message)
}

// CtxVersionKey is the gin context key holding the API version, set by the
// router middleware.
const CtxVersionKey = "apiVersion"

// apiVersionFromContext pulls the API version that the router stored on the
// request context.
func apiVersionFromContext(c *gin.Context) string {
	if version, ok := c.Get(CtxVersionKey); ok {
		if s, ok := version.(string); ok {
			return s
		}
	}
	return "v1"
}
