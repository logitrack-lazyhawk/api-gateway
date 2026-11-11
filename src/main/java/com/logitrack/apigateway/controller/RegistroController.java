package com.logitrack.apigateway.controller;

import com.logitrack.apigateway.service.KeycloakRegistrationService;
import com.logitrack.apigateway.util.JwtUtil;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class RegistroController {

    private final KeycloakRegistrationService registrationService;
    private final JwtUtil jwtUtil;

    public RegistroController(KeycloakRegistrationService registrationService, JwtUtil jwtUtil) {
        this.registrationService = registrationService;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/registro")
    public Mono<ResponseEntity<Map<String, Object>>> registrar(@RequestBody Map<String, Object> payload) {
        return Mono.fromCallable(() -> registrationService.registrarUsuario(payload));
    }

    @GetMapping("/me")
    public Mono<ResponseEntity<Map<String, Object>>> me(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authHeader) {
        return Mono.fromCallable(() -> {
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Token de autenticación no proporcionado"));
            }

            String token = authHeader.substring(7).trim();

            if (!jwtUtil.isTokenValid(token)) {
                // Soporte tolerante para tokens locales de desarrollo (jwt-<rol>-<timestamp>)
                if (token.startsWith("jwt-")) {
                    String[] partes = token.split("-");
                    String rol = partes.length > 1 ? partes[1].toUpperCase() : "CLIENTE";
                    Map<String, Object> perfil = new LinkedHashMap<>();
                    perfil.put("email", rol.toLowerCase() + "@logitrack.com");
                    perfil.put("rol", rol);
                    perfil.put("roles", List.of(rol));
                    perfil.put("activo", true);

                    Map<String, Object> resp = new LinkedHashMap<>();
                    resp.put("mensaje", "Sesión local válida");
                    resp.put("datos", perfil);
                    return ResponseEntity.ok(resp);
                }
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Token inválido o expirado"));
            }

            String email = jwtUtil.extractUsername(token);
            List<String> roles = jwtUtil.extractRoles(token);
            String primaryRole = roles.contains("ADMIN") ? "ADMIN" :
                    roles.contains("CLIENTE") ? "CLIENTE" :
                    roles.contains("REPARTIDOR") ? "REPARTIDOR" :
                    roles.contains("VENDEDOR") ? "VENDEDOR" :
                    (!roles.isEmpty() ? roles.get(0) : "CLIENTE");

            Map<String, Object> perfil = new LinkedHashMap<>();
            perfil.put("email", email);
            perfil.put("rol", primaryRole);
            perfil.put("roles", roles);
            perfil.put("activo", true);

            Map<String, Object> resp = new LinkedHashMap<>();
            resp.put("mensaje", "Sesión válida");
            resp.put("datos", perfil);

            return ResponseEntity.ok(resp);
        });
    }
}

