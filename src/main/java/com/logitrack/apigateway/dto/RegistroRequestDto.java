package com.logitrack.apigateway.dto;

public record RegistroRequestDto(
        String email,
        String password,
        String rol,
        String nombre,
        String apellido
) {}

