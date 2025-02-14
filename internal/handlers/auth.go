package handlers

import (
	"net/http"
	"strconv"

	"github.com/Cheyzie/chat_auth/internal/model"
	"github.com/gin-gonic/gin"
)

func (h *Handler) signIn(ctx *gin.Context) {
	var input model.SigninInput
	if err := ctx.ShouldBindJSON(&input); err != nil {
		newErrorResponse(ctx, http.StatusUnauthorized, "Invalid input. Expected email and password", err)
		return
	}

	token, err := h.authService.GenerateToken(input.Email, input.Password, input.SessionName)
	if err != nil {
		newErrorResponse(ctx, http.StatusUnauthorized, "Invalid credentials", err)
		return
	}
	ctx.JSON(http.StatusOK, token)

}

func (h *Handler) userSessions(ctx *gin.Context) {
	id, err := getUserId(ctx)

	if err != nil {
		newErrorResponse(ctx, http.StatusUnauthorized, "cant resolve user id", err)
		return
	}
	sessions, err := h.authService.ListUserSessions(id)
	if err != nil {
		newErrorResponse(ctx, http.StatusInternalServerError, "cant get sessions", err)
		return
	}
	ctx.JSON(http.StatusOK, sessions)
}

func (h *Handler) refreshToken(ctx *gin.Context) {
	var input model.RefreshInput
	if err := ctx.ShouldBindJSON(&input); err != nil {
		newErrorResponse(ctx, http.StatusUnauthorized, "Invalid input. Expected refresh_token", err)
		return
	}

	token, err := h.authService.RefreshToken(input.RefreshToken)
	if err != nil {
		newErrorResponse(ctx, http.StatusUnauthorized, "Invalid credentials", err)
		return
	}
	ctx.JSON(http.StatusOK, token)

}

func (h *Handler) signUp(ctx *gin.Context) {
	var input model.User
	if err := ctx.ShouldBindJSON(&input); err != nil {
		newErrorResponse(ctx, http.StatusUnprocessableEntity, "Invalid input. Expected username, email and password", err)
		return
	}

	id, err := h.authService.CreateUser(input)
	if err != nil {
		newErrorResponse(ctx, http.StatusBadRequest, "Invalid data", err)
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		"id": id,
	})
}

func (h *Handler) getMe(ctx *gin.Context) {
	id, err := getUserId(ctx)

	if err != nil {
		newErrorResponse(ctx, http.StatusUnauthorized, "cant resolve user id", err)
		return
	}
	user, err := h.authService.GetByID(id)
	if err != nil {
		newErrorResponse(ctx, http.StatusInternalServerError, "cant find user by id", err)
		return
	}

	ctx.JSON(http.StatusOK, user)
}

func (h *Handler) dropSession(ctx *gin.Context) {
	userID, err := getUserId(ctx)

	if err != nil {
		newErrorResponse(ctx, http.StatusUnauthorized, "cant resolve user id", err)
		return
	}

	sessionID, err := strconv.Atoi(ctx.Param("id"))
	if err != nil {
		newErrorResponse(ctx, http.StatusBadRequest, "cant parse session id", err)
		return
	}

	if err := h.authService.DropSession(userID, uint(sessionID)); err != nil {
		newErrorResponse(ctx, http.StatusInternalServerError, "cant drop sessions", err)
		return
	}
	ctx.JSON(http.StatusNoContent, nil)
}

func (h *Handler) signOut(ctx *gin.Context) {
	userID, err := getUserId(ctx)
	if err != nil {
		newErrorResponse(ctx, http.StatusUnauthorized, "cant resolve user id", err)
		return
	}

	sessionID, err := getSessionId(ctx)
	if err != nil {
		newErrorResponse(ctx, http.StatusUnauthorized, "cant resolve session id", err)
		return
	}

	if err := h.authService.DropSession(userID, sessionID); err != nil {
		newErrorResponse(ctx, http.StatusInternalServerError, "cant drop sessions", err)
		return
	}
	ctx.JSON(http.StatusNoContent, nil)
}
