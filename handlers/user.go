package handlers

import (
	"github.com/Marmotte-40K/backend-owasp/services"
)

type UserHandler struct {
	svcUser *services.UserService
}

func NewUserHandler(svcUser *services.UserService) *UserHandler {
	return &UserHandler{
		svcUser: svcUser,
	}
}
