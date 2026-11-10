package com.logitrack.apigateway.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.logitrack.apigateway.dto.*;
import com.logitrack.apigateway.util.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;

@Service
public class KeycloakAuthService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakAuthService.class);

    private final JwtUtil jwtUtil;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3))
            .build();

    @Value("${keycloak.url:${KEYCLOAK_URL:http://keycloak:8080}}")
    private String primaryKeycloakUrl;

    @Value("${keycloak.fallback-url:${KEYCLOAK_FALLBACK_URL:http://localhost:8082}}")
    private String fallbackKeycloakUrl;

    @Value("${keycloak.realm:lazyhawk}")
    private String realm;

    @Value("${keycloak.client-id:logitrack-frontend}")
    private String clientId;

    @Value("${keycloak.admin.user:admin}")
    private String adminUser;

    @Value("${keycloak.admin.password:admin}")
    private String adminPassword;

    public KeycloakAuthService(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    public AuthResponseDto login(LoginRequestDto request) {
        String username = request.getResolvedUsername();
        String password = request.password();
        if (username.isBlank() || password == null || password.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Debe ingresar usuario/email y contraseña");
        }

        String formBody = "grant_type=password"
                + "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                + "&username=" + URLEncoder.encode(username, StandardCharsets.UTF_8)
                + "&password=" + URLEncoder.encode(password, StandardCharsets.UTF_8);

        HttpResponse<String> response = sendWithFallback(
                "/realms/" + realm + "/protocol/openid-connect/token",
                "POST",
                "application/x-www-form-urlencoded",
                formBody,
                null
        );

        if (response.statusCode() == 200) {
            try {
                JsonNode json = objectMapper.readTree(response.body());
                String accessToken = json.get("access_token").asText();
                long expiresIn = json.has("expires_in") ? json.get("expires_in").asLong() : 300L;

                List<String> roles = jwtUtil.extractRoles(accessToken);
                String tokenUser = jwtUtil.extractUsername(accessToken);

                String primaryRole = roles.stream()
                        .filter(r -> !r.startsWith("default-roles"))
                        .findFirst()
                        .orElse("CLIENTE");

                return new AuthResponseDto(
                        accessToken,
                        tokenUser != null ? tokenUser : username,
                        primaryRole,
                        roles,
                        "Bearer",
                        expiresIn
                );
            } catch (Exception e) {
                log.error("Error procesando respuesta de Keycloak: {}", e.getMessage(), e);
                throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error procesando autenticación");
            }
        } else if (response.statusCode() == 400 || response.statusCode() == 401) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Credenciales inválidas");
        } else {
            log.error("Error en servidor Keycloak: status={}, body={}", response.statusCode(), response.body());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Servidor de autenticación no disponible");
        }
    }

    public RegistroResponseDto registrar(RegistroRequestDto request) {
        if (request.email() == null || request.email().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "El email es obligatorio");
        }
        if (request.password() == null || request.password().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "La contraseña es obligatoria");
        }

        String adminToken = obtainAdminToken();

        // 1. Crear usuario en Keycloak
        Map<String, Object> userPayload = new LinkedHashMap<>();
        userPayload.put("username", request.email().trim());
        userPayload.put("email", request.email().trim());
        userPayload.put("firstName", request.nombre() != null ? request.nombre() : "");
        userPayload.put("lastName", request.apellido() != null ? request.apellido() : "");
        userPayload.put("enabled", true);
        userPayload.put("emailVerified", true);
        userPayload.put("credentials", List.of(
                Map.of("type", "password", "value", request.password(), "temporary", false)
        ));

        String jsonBody;
        try {
            jsonBody = objectMapper.writeValueAsString(userPayload);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error generando payload de usuario");
        }

        HttpResponse<String> createResponse = sendWithFallback(
                "/admin/realms/" + realm + "/users",
                "POST",
                "application/json",
                jsonBody,
                adminToken
        );

        if (createResponse.statusCode() == 409) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "El email ya se encuentra registrado en el sistema.");
        }
        if (createResponse.statusCode() != 201) {
            log.error("Error registrando usuario en Keycloak: status={}, body={}", createResponse.statusCode(), createResponse.body());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error al registrar usuario en Keycloak");
        }

        // 2. Asignar rol
        String roleToAssign = (request.rol() != null && !request.rol().isBlank())
                ? request.rol().trim().toUpperCase()
                : "CLIENTE";
        if (roleToAssign.startsWith("ROLE_")) {
            roleToAssign = roleToAssign.substring(5);
        }

        String userId = null;
        Optional<String> locationHeader = createResponse.headers().firstValue("Location");
        if (locationHeader.isPresent()) {
            String loc = locationHeader.get();
            userId = loc.substring(loc.lastIndexOf('/') + 1);
        }

        if (userId != null && !roleToAssign.equalsIgnoreCase("CLIENTE")) {
            assignRoleToUser(userId, roleToAssign, adminToken);
        }

        return new RegistroResponseDto(
                "Usuario registrado correctamente.",
                new UsuarioPerfilDto(userId, request.email(), roleToAssign, true)
        );
    }

    private String obtainAdminToken() {
        String formBody = "grant_type=password&client_id=admin-cli"
                + "&username=" + URLEncoder.encode(adminUser, StandardCharsets.UTF_8)
                + "&password=" + URLEncoder.encode(adminPassword, StandardCharsets.UTF_8);

        HttpResponse<String> response = sendWithFallback(
                "/realms/master/protocol/openid-connect/token",
                "POST",
                "application/x-www-form-urlencoded",
                formBody,
                null
        );

        if (response.statusCode() == 200) {
            try {
                JsonNode json = objectMapper.readTree(response.body());
                return json.get("access_token").asText();
            } catch (Exception e) {
                throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error decodificando token admin");
            }
        }
        log.error("Fallo obteniendo token admin de Keycloak: status={}, body={}", response.statusCode(), response.body());
        throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "No fue posible autenticar contra Keycloak");
    }

    private void assignRoleToUser(String userId, String roleName, String adminToken) {
        try {
            HttpResponse<String> roleResponse = sendWithFallback(
                    "/admin/realms/" + realm + "/roles/" + URLEncoder.encode(roleName, StandardCharsets.UTF_8),
                    "GET",
                    "application/json",
                    null,
                    adminToken
            );
            if (roleResponse.statusCode() == 200) {
                JsonNode roleJson = objectMapper.readTree(roleResponse.body());
                String roleMappingBody = objectMapper.writeValueAsString(List.of(roleJson));

                sendWithFallback(
                        "/admin/realms/" + realm + "/users/" + userId + "/role-mappings/realm",
                        "POST",
                        "application/json",
                        roleMappingBody,
                        adminToken
                );
            }
        } catch (Exception e) {
            log.warn("No se pudo asignar rol {} al usuario {}: {}", roleName, userId, e.getMessage());
        }
    }

    private HttpResponse<String> sendWithFallback(
            String path,
            String method,
            String contentType,
            String body,
            String bearerToken
    ) {
        List<String> baseUrls = new ArrayList<>();
        if (primaryKeycloakUrl != null && !primaryKeycloakUrl.isBlank()) {
            baseUrls.add(primaryKeycloakUrl.replaceAll("/+$", ""));
        }
        if (fallbackKeycloakUrl != null && !fallbackKeycloakUrl.isBlank() && !fallbackKeycloakUrl.equals(primaryKeycloakUrl)) {
            baseUrls.add(fallbackKeycloakUrl.replaceAll("/+$", ""));
        }

        Exception lastEx = null;
        for (String baseUrl : baseUrls) {
            try {
                HttpRequest.Builder builder = HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl + path))
                        .timeout(Duration.ofSeconds(4));

                if (contentType != null) {
                    builder.header("Content-Type", contentType);
                }
                if (bearerToken != null) {
                    builder.header("Authorization", "Bearer " + bearerToken);
                }

                if ("POST".equalsIgnoreCase(method)) {
                    builder.POST(HttpRequest.BodyPublishers.ofString(body != null ? body : ""));
                } else if ("GET".equalsIgnoreCase(method)) {
                    builder.GET();
                }

                HttpResponse<String> resp = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
                // Si respondió el servidor (incluso 4xx/5xx), la conexión fue exitosa
                return resp;
            } catch (Exception e) {
                lastEx = e;
                log.debug("Fallo de conexión a Keycloak en {}{}: {}", baseUrl, path, e.getMessage());
            }
        }
        throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                "No fue posible comunicarse con Keycloak en " + baseUrls + ": " + (lastEx != null ? lastEx.getMessage() : "Error de red"));
    }
}

