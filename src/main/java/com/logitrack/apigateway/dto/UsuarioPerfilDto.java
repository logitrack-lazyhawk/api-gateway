package com.logitrack.apigateway.dto;

public record UsuarioPerfilDto(
        String id,
        String email,
        String rol,
        boolean activo
) {}

