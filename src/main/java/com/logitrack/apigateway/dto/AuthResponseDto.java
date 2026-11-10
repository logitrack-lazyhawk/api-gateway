package com.logitrack.apigateway.dto;

import java.util.List;

public record AuthResponseDto(
        String token,
        String email,
        String rol,
        List<String> roles,
        String tokenType,
        Long expiresIn
) {}

