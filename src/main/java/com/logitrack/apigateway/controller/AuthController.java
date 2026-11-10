package com.logitrack.apigateway.controller;

import com.logitrack.apigateway.dto.*;
import com.logitrack.apigateway.service.KeycloakAuthService;
import com.logitrack.apigateway.util.JwtUtil;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Controlador de Autenticación del API Gateway.
 * Expone /api/auth/login, /api/auth/registro y /api/auth/me delegando directamente en Keycloak.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final KeycloakAuthService keycloakAuthService;
    private final JwtUtil jwtUtil;

    public AuthController(KeycloakAuthService keycloakAuthService, JwtUtil jwtUtil) {
        this.keycloakAuthService = keycloakAuthService;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/login")
    public Mono<ResponseEntity<Object>> login(@RequestBody LoginRequestDto request) {
        return Mono.fromCallable(() -> keycloakAuthService.login(request))
                .map(res -> ResponseEntity.ok((Object) res))
                .onErrorResume(ex -> Mono.just(handleError(ex, "/api/auth/login")));
    }

    @PostMapping("/registro")
    public Mono<ResponseEntity<Object>> registrar(@RequestBody RegistroRequestDto request) {
        return Mono.fromCallable(() -> keycloakAuthService.registrar(request))
                .map(res -> ResponseEntity.status(HttpStatus.CREATED).body((Object) res))
                .onErrorResume(ex -> Mono.just(handleError(ex, "/api/auth/registro")));
    }

    @GetMapping("/me")
    public Mono<ResponseEntity<Object>> me(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorBody(401, "Unauthorized", "Debe ingresar un token de autenticación.", "/api/auth/me")));
        }
        String token = authHeader.substring(7).trim();
        if (!jwtUtil.isTokenValid(token)) {
            return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorBody(401, "Unauthorized", "El token es inválido o ha expirado.", "/api/auth/me")));
        }

        String username = jwtUtil.extractUsername(token);
        var roles = jwtUtil.extractRoles(token);
        String primaryRole = roles.stream().filter(r -> !r.startsWith("default-roles")).findFirst().orElse("CLIENTE");

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("message", "Token válido. Usuario autenticado correctamente.");
        body.put("usuario", Map.of(
                "email", username != null ? username : "",
                "rol", primaryRole,
                "roles", roles
        ));

        return Mono.just(ResponseEntity.ok((Object) body));
    }

    private ResponseEntity<Object> handleError(Throwable ex, String path) {
        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
        String message = ex.getMessage();

        if (ex instanceof ResponseStatusException rse) {
            status = HttpStatus.valueOf(rse.getStatusCode().value());
            message = rse.getReason() != null ? rse.getReason() : rse.getMessage();
        } else if (ex.getCause() instanceof ResponseStatusException rse) {
            status = HttpStatus.valueOf(rse.getStatusCode().value());
            message = rse.getReason() != null ? rse.getReason() : rse.getMessage();
        }

        return ResponseEntity.status(status).body(errorBody(status.value(), status.getReasonPhrase(), message, path));
    }

    private Map<String, Object> errorBody(int status, String error, String message, String path) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("timestamp", LocalDateTime.now().toString());
        map.put("status", status);
        map.put("error", error);
        map.put("message", message);
        map.put("path", path);
        return map;
    }
}
