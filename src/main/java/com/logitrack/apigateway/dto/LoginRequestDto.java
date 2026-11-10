package com.logitrack.apigateway.dto;

public record LoginRequestDto(
        String email,
        String username,
        String password
) {
    public String getResolvedUsername() {
        if (email != null && !email.isBlank()) {
            return email.trim();
        }
        return username != null ? username.trim() : "";
    }
}

