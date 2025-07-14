package middleware

import (
	"bytes"
	"encoding/json"
	"io"

	"log"

	"github.com/Marmotte-40K/backend-owasp/pkg"
	"github.com/gin-gonic/gin"
)

func LogRequestResponse() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Leggi e salva il body originale
		var body map[string]interface{}
		var buf bytes.Buffer
		if c.Request.Body != nil {
			tee := io.TeeReader(c.Request.Body, &buf)
			_ = json.NewDecoder(tee).Decode(&body)
			c.Request.Body = io.NopCloser(&buf)
		}

		if body != nil {
			body = pkg.MaskSensitiveData(body)
		}

		log.SetOutput(pkg.GetLogWriter("request-response"))
		log.Printf("Request: %s %s Body: %+v IP: %s", c.Request.Method, c.Request.URL.Path, body, c.ClientIP())

		// Cattura la response
		c.Next()
		status := c.Writer.Status()
		log.Printf("Response: %s %s Status: %d  IP: %s", c.Request.Method, c.Request.URL.Path, status, c.ClientIP())
	}
}
