package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/Cheyzie/chat_auth/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	authorizationHeader = "Authorization"
	userCtx             = "userId"
	sessionCtx          = "session"
)

func (h *Handler) userIdentity(c *gin.Context) {
	header := c.GetHeader(authorizationHeader)
	if header == "" {
		newErrorResponse(c, http.StatusUnauthorized, "empty auth header", nil)
		return
	}

	headerParts := strings.Split(header, " ")
	if len(headerParts) != 2 || headerParts[0] != "Bearer" {
		newErrorResponse(c, http.StatusUnauthorized, "invalid auth header", nil)
		return
	}

	if len(headerParts[1]) == 0 {
		newErrorResponse(c, http.StatusUnauthorized, "token is empty", nil)
		return
	}

	claims, err := h.authService.ParseToken(headerParts[1])
	if err != nil {
		newErrorResponse(c, http.StatusUnauthorized, "invalid token", err)
		return
	}

	if _, err := h.authService.FindSession(c.Request.Context(), claims.SessionID); err != nil {
		if errors.Is(err, service.ErrNotFound) {
			newErrorResponse(c, http.StatusUnauthorized, "invalid token", err)
			return
		}
		newErrorResponse(c, http.StatusInternalServerError, "something went wrong", err)
		return
	}
	c.Set(userCtx, claims.UserId)
	c.Set(sessionCtx, claims.SessionID)
}

func getUserId(c *gin.Context) (uuid.UUID, error) {
	id, ok := c.Get(userCtx)
	if !ok {
		return uuid.Nil, errors.New("user id not found")
	}

	idUUID, ok := id.(uuid.UUID)
	if !ok {
		return uuid.Nil, errors.New("user id is of invalid type")
	}

	return idUUID, nil
}

func getSessionId(c *gin.Context) (uuid.UUID, error) {
	id, ok := c.Get(sessionCtx)
	if !ok {
		return uuid.Nil, errors.New("session id not found")
	}

	idUUID, ok := id.(uuid.UUID)
	if !ok {
		return uuid.Nil, errors.New("session id is of invalid type")
	}

	return idUUID, nil
}
