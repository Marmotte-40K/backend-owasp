package handlers

import (
	"net/http"
	"os"
	"time"

	"github.com/Marmotte-40K/backend-owasp/models"
	"github.com/Marmotte-40K/backend-owasp/pkg"
	"github.com/Marmotte-40K/backend-owasp/services"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandler struct {
	svcUser  *services.UserService
	svcToken *services.TokenService
}

func NewAuthHandler(svcUser *services.UserService, svcToken *services.TokenService) *AuthHandler {
	return &AuthHandler{
		svcUser:  svcUser,
		svcToken: svcToken,
	}
}

var domain = os.Getenv("DOMAIN")

type loginBody struct {
	Email    string `json:"email"  binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
	TOTPCode string `json:"totp_code,omitempty"`
}

func (h *AuthHandler) Login(c *gin.Context) {
	var body loginBody

	if err := c.ShouldBindJSON(&body); err != nil {
		pkg.LogError(
			"Login",
			err,
			map[string]interface{}{
				"email": body.Email,
				"ip":    c.ClientIP(),
			},
		)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid"})
		return
	}

	user, err := h.svcUser.GetUserByEmail(c.Request.Context(), body.Email)

	if err != nil {
		pkg.LogError(
			"Login",
			err,
			map[string]interface{}{
				"email": body.Email,
				"ip":    c.ClientIP(),
			},
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	if user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "account locked", "locked_until": user.LockedUntil})
		return
	}

	if err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password)); err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			pkg.LogFailedLogin(
				map[string]interface{}{
					"id":    user.ID,
					"email": body.Email,
					"ip":    c.ClientIP(),
				},
			)
			user.FailedLoginAttempts++
			if user.FailedLoginAttempts >= 5 {
				lockUntil := time.Now().Add(10 * time.Minute)
				err = h.svcUser.UpdateFailedAttemptsAndLock(c.Request.Context(), user.ID, user.FailedLoginAttempts, &lockUntil)
				if err != nil {
					pkg.LogError(
						"Login",
						err,
						map[string]interface{}{
							"id":    user.ID,
							"email": body.Email,
							"ip":    c.ClientIP(),
						},
					)
					c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
					return
				}
				c.JSON(http.StatusUnauthorized, gin.H{"error": "account locked", "locked_until": lockUntil})
				return
			} else {
				err = h.svcUser.UpdateFailedAttemptsAndLock(c.Request.Context(), user.ID, user.FailedLoginAttempts, nil)
				if err != nil {
					pkg.LogError(
						"Login",
						err,
						map[string]interface{}{
							"id":    user.ID,
							"email": body.Email,
							"ip":    c.ClientIP(),
						},
					)
					c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
					return
				}
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
				return
			}
		}
		pkg.LogError(
			"Login",
			err,
			map[string]interface{}{
				"id":    user.ID,
				"email": body.Email,
				"ip":    c.ClientIP(),
			},
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	if user.TotpEnabled {
		if body.TOTPCode == "" {
			pkg.LogError(
				"TOTP Required",
				nil,
				map[string]interface{}{
					"email": body.Email,
					"ip":    c.ClientIP(),
				},
			)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "TOTP code required", "totp_required": true})
			return
		}

		totpService := services.NewTOTPService(nil)
		if !totpService.ValidateCode(body.TOTPCode, user.TotpSecret) {
			pkg.LogFailedLogin(
				map[string]interface{}{
					"id":    user.ID,
					"email": body.Email,
					"ip":    c.ClientIP(),
				},
			)
			user.FailedLoginAttempts++
			if user.FailedLoginAttempts >= 5 {
				lockUntil := time.Now().Add(10 * time.Minute)
				err = h.svcUser.UpdateFailedAttemptsAndLock(c.Request.Context(), user.ID, user.FailedLoginAttempts, &lockUntil)
				if err != nil {
					pkg.LogError(
						"TOTP Validation Error",
						err,
						map[string]interface{}{
							"id":    user.ID,
							"email": body.Email,
							"ip":    c.ClientIP(),
						},
					)
					c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
					return
				}
				c.JSON(http.StatusUnauthorized, gin.H{"error": "account locked", "locked_until": lockUntil})
				return
			} else {
				err = h.svcUser.UpdateFailedAttemptsAndLock(c.Request.Context(), user.ID, user.FailedLoginAttempts, nil)
				if err != nil {
					pkg.LogError(
						"TOTP Validation Error",
						err,
						map[string]interface{}{
							"id":    user.ID,
							"email": body.Email,
							"ip":    c.ClientIP(),
						},
					)
					c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
					return
				}
			}
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid TOTP code"})
			return
		}
	}

	err = h.svcUser.UpdateFailedAttemptsAndLock(c.Request.Context(), user.ID, 0, nil)
	if err != nil {
		pkg.LogError(
			"Login",
			err,
			map[string]interface{}{
				"id":    user.ID,
				"email": body.Email,
				"ip":    c.ClientIP(),
			},
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	dbToken, err := h.svcToken.GetRefreshToken(c.Request.Context(), user.ID)
	if err != nil && err.Error() != "no rows in result set" {
		pkg.LogError(
			"Login",
			err,
			map[string]interface{}{
				"id":    user.ID,
				"email": body.Email,
				"ip":    c.ClientIP(),
			},
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	if dbToken != "" {
		err = h.svcToken.RemoveRefreshToken(c.Request.Context(), user.ID)
		if err != nil {
			pkg.LogError(
				"Login",
				err,
				map[string]interface{}{
					"id":    user.ID,
					"email": body.Email,
					"ip":    c.ClientIP(),
				},
			)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}
	}

	expToken := time.Now().Add(15 * time.Minute)
	token, err := pkg.CreateToken(user.ID, expToken.Unix())
	if err != nil {
		pkg.LogError(
			"Login",
			err,
			map[string]interface{}{
				"id":    user.ID,
				"email": body.Email,
				"ip":    c.ClientIP(),
			},
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	expRefresh := time.Now().Add(time.Hour * 24 * 7)

	refreshToken, err := pkg.CreateToken(user.ID, expRefresh.Unix())
	if err != nil {
		pkg.LogError(
			"Login",
			err,
			map[string]interface{}{
				"id":    user.ID,
				"email": body.Email,
				"ip":    c.ClientIP(),
			},
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	err = h.svcToken.AddRefreshToken(c.Request.Context(), user.ID, refreshToken, expRefresh)
	if err != nil {
		pkg.LogError(
			"Login",
			err,
			map[string]interface{}{
				"id":    user.ID,
				"email": body.Email,
				"ip":    c.ClientIP(),
			},
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.SetCookie("access_token", token, int(time.Until(expToken).Seconds()), "/", domain, false, true)
	c.SetCookie("refresh_token", refreshToken, int(time.Until(expRefresh).Seconds()), "/", domain, false, true)

	c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
}

type registerBody struct {
	Name     string `json:"name" binding:"required,min=2,max=50"`
	Surname  string `json:"surname" binding:"required,min=2,max=100"`
	Email    string `json:"email"  binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

func (h *AuthHandler) Register(c *gin.Context) {
	var body registerBody

	if err := c.ShouldBindJSON(&body); err != nil {
		pkg.LogError(
			"Register",
			err,
			map[string]interface{}{
				"email": body.Email,
				"ip":    c.ClientIP(),
			},
		)

		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}

	body.Name = pkg.StripHTMLTags(body.Name)
	body.Surname = pkg.StripHTMLTags(body.Surname)
	body.Email = pkg.StripHTMLTags(body.Email)

	if len(body.Name) < 2 || len(body.Name) > 50 || len(body.Surname) < 2 || len(body.Surname) > 100 {
		pkg.LogError(
			"Register",
			nil,
			map[string]interface{}{
				"email": body.Email,
				"ip":    c.ClientIP(),
			},
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": "name or surname length is invalid"})
		return
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		pkg.LogError(
			"Register",
			err,
			map[string]interface{}{
				"email": body.Email,
				"ip":    c.ClientIP(),
			},
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	user, err := h.svcUser.CreateUser(c, &models.User{Name: body.Name, Surname: body.Surname, Email: body.Email, Password: string(hashed)})
	if err != nil {
		pkg.LogError(
			"Register",
			err,
			map[string]interface{}{
				"email": body.Email,
				"ip":    c.ClientIP(),
			},
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	expToken := time.Now().Add(15 * time.Minute)
	token, err := pkg.CreateToken(user.ID, expToken.Unix())
	if err != nil {
		pkg.LogError(
			"Register",
			err,
			map[string]interface{}{
				"email": body.Email,
				"ip":    c.ClientIP(),
			},
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	expRefresh := time.Now().Add(time.Hour * 24 * 7)

	refreshToken, err := pkg.CreateToken(user.ID, expRefresh.Unix())
	if err != nil {
		pkg.LogError(
			"Register",
			err,
			map[string]interface{}{
				"email": body.Email,
				"ip":    c.ClientIP(),
			},
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	err = h.svcToken.AddRefreshToken(c.Request.Context(), user.ID, refreshToken, expRefresh)
	if err != nil {
		pkg.LogError(
			"Register",
			err,
			map[string]interface{}{
				"email": body.Email,
				"ip":    c.ClientIP(),
			},
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.SetCookie("access_token", token, int(time.Until(expToken).Seconds()), "/", domain, false, true)
	c.SetCookie("refresh_token", refreshToken, int(time.Until(expRefresh).Seconds()), "/", domain, false, true)

	c.JSON(http.StatusOK, gin.H{"message": "Registration successful"})
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		pkg.LogError(
			"Refresh Token",
			err,
			map[string]interface{}{
				"ip": c.ClientIP(),
			},
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}

	err = pkg.ValidateToken(refreshToken)
	if err != nil {
		pkg.LogError(
			"Refresh Token",
			err,
			map[string]interface{}{
				"ip": c.ClientIP(),
			},
		)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}

	userID, err := pkg.GetUserIDFromToken(refreshToken)
	if err != nil {
		pkg.LogError(
			"Refresh Token",
			err,
			map[string]interface{}{
				"ip": c.ClientIP(),
			},
		)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}

	dbToken, err := h.svcToken.GetRefreshToken(c.Request.Context(), userID)
	if err != nil {
		pkg.LogError(
			"Refresh Token",
			err,
			map[string]interface{}{
				"id": userID,
				"ip": c.ClientIP(),
			},
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	if dbToken != refreshToken {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}

	expToken := time.Now().Add(15 * time.Minute)
	newToken, err := pkg.CreateToken(int64(userID), expToken.Unix())
	if err != nil {
		pkg.LogError(
			"Refresh Token",
			err,
			map[string]interface{}{
				"id": userID,
				"ip": c.ClientIP(),
			},
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.SetCookie("access_token", newToken, int(expToken.Second()), "/", domain, false, true)

	c.JSON(http.StatusOK, gin.H{"message": "Token refreshed successfully"})
}

func (h *AuthHandler) Logout(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		pkg.LogError(
			"Logout",
			err,
			map[string]interface{}{
				"ip": c.ClientIP(),
			},
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}

	userID, err := pkg.GetUserIDFromToken(refreshToken)
	if err != nil {
		pkg.LogError(
			"Logout",
			err,
			map[string]interface{}{
				"ip": c.ClientIP(),
			},
		)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}

	err = h.svcToken.RemoveRefreshToken(c.Request.Context(), userID)
	if err != nil {
		pkg.LogError(
			"Logout",
			err,
			map[string]interface{}{
				"id": userID,
				"ip": c.ClientIP(),
			},
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	c.SetCookie("refresh_token", "", -1, "/", domain, false, true)
	c.SetCookie("access_token", "", -1, "/", domain, false, true)

	c.JSON(http.StatusOK, gin.H{
		"message": "Logout successful",
	})
}

func (h *AuthHandler) Me(c *gin.Context) {
	tokenString, err := c.Cookie("access_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
		return
	}
	userID, err := pkg.GetUserIDFromToken(tokenString)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}
	user, err := h.svcUser.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		pkg.LogError(
			"Get User",
			err,
			map[string]interface{}{
				"id": userID,
				"ip": c.ClientIP(),
			},
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	c.JSON(200, gin.H{
		"id":           user.ID,
		"name":         user.Name,
		"surname":      user.Surname,
		"email":        user.Email,
		"totp_enabled": user.TotpEnabled,
	})
}

type changePasswordBody struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
	TOTPCode    string `json:"totp_code,omitempty"`
}

func (h *AuthHandler) ChangePassword(c *gin.Context) {
	tokenString, err := c.Cookie("access_token")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
		return
	}
	userID, err := pkg.GetUserIDFromToken(tokenString)
	if err != nil {
		pkg.LogError(
			"ChangePassword",
			err,
			map[string]interface{}{"ip": c.ClientIP()},
		)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}
	user, err := h.svcUser.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		pkg.LogError(
			"ChangePassword",
			err,
			map[string]interface{}{"id": userID, "ip": c.ClientIP()},
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	var body changePasswordBody
	if err := c.ShouldBindJSON(&body); err != nil {
		pkg.LogError(
			"ChangePassword",
			err,
			map[string]interface{}{"id": userID, "ip": c.ClientIP()},
		)
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.OldPassword)); err != nil {
		pkg.LogFailedLogin(map[string]interface{}{
			"id": user.ID, "email": user.Email, "ip": c.ClientIP(),
		})
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	if user.TotpEnabled {
		if body.TOTPCode == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "TOTP code required"})
			return
		}
		totpService := services.NewTOTPService(nil)
		if !totpService.ValidateCode(body.TOTPCode, user.TotpSecret) {
			pkg.LogFailedLogin(map[string]interface{}{
				"id": user.ID, "email": user.Email, "ip": c.ClientIP(),
			})
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid TOTP code"})
			return
		}
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(body.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		pkg.LogError(
			"ChangePassword",
			err,
			map[string]interface{}{"id": userID, "ip": c.ClientIP()},
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}
	err = h.svcUser.UpdatePassword(c.Request.Context(), userID, string(hashed))
	if err != nil {
		pkg.LogError(
			"ChangePassword",
			err,
			map[string]interface{}{"id": userID, "ip": c.ClientIP()},
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	err = h.svcToken.RemoveRefreshToken(c.Request.Context(), userID)
	if err != nil {
		pkg.LogError(
			"ChangePassword - RemoveRefreshToken",
			err,
			map[string]interface{}{"id": userID, "ip": c.ClientIP()},
		)
	}

	c.SetCookie("access_token", "", -1, "/", domain, false, true)
	c.SetCookie("refresh_token", "", -1, "/", domain, false, true)

	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}
