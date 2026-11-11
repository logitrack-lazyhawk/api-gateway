package com.logitrack.apigateway.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;

@Service
public class KeycloakRegistrationService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakRegistrationService.class);

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3))
            .build();

    @Value("${KEYCLOAK_URI:${keycloak.url:http://keycloak:8080}}")
    private String primaryKeycloakUrl;

    @Value("${keycloak.fallback-url:http://localhost:8082}")
    private String fallbackKeycloakUrl;

    @Value("${keycloak.realm:lazyhawk}")
    private String realm;

    @Value("${KEYCLOAK_ADMIN:${keycloak.admin.user:admin}}")
    private String adminUser;

    @Value("${KEYCLOAK_ADMIN_PASSWORD:${keycloak.admin.password:admin}}")
    private String adminPassword;

    public ResponseEntity<Map<String, Object>> registrarUsuario(Map<String, Object> payloadMap) {
        if (payloadMap == null || payloadMap.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "El cuerpo de la petición debe ser un objeto JSON"));
        }
        JsonNode payload = objectMapper.valueToTree(payloadMap);
        return registrarUsuario(payload);
    }

    public ResponseEntity<Map<String, Object>> registrarUsuario(JsonNode payload) {
        if (payload == null || !payload.isObject()) {
            return ResponseEntity.badRequest().body(Map.of("error", "El cuerpo de la petición debe ser un objeto JSON"));
        }

        ObjectNode userNode = payload.deepCopy();

        // 1. Extraer o normalizar campos requeridos
        String email = userNode.hasNonNull("email") ? userNode.get("email").asText().trim() : "";
        String username = userNode.hasNonNull("username") ? userNode.get("username").asText().trim() : "";

        if (username.isBlank() && !email.isBlank()) {
            username = email;
            userNode.put("username", username);
        } else if (!username.isBlank() && email.isBlank()) {
            email = username;
            userNode.put("email", email);
        }

        if (username.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Debe especificar 'username' o 'email'"));
        }

        // Habilitar por defecto
        if (!userNode.has("enabled")) {
            userNode.put("enabled", true);
        }
        if (!userNode.has("emailVerified")) {
            userNode.put("emailVerified", true);
        }
        // Limpiar acciones requeridas pendientes para permitir login inmediato
        if (!userNode.has("requiredActions")) {
            userNode.putArray("requiredActions");
        }

        // Asegurar firstName y lastName (requeridos por el User Profile de Keycloak)
        String firstName = userNode.hasNonNull("firstName") ? userNode.get("firstName").asText().trim() : "";
        if (firstName.isBlank() && userNode.hasNonNull("nombre")) {
            firstName = userNode.get("nombre").asText().trim();
            userNode.put("firstName", firstName);
        }
        if (firstName.isBlank()) {
            firstName = username.contains("@") ? username.substring(0, username.indexOf('@')) : username;
            userNode.put("firstName", firstName);
        }

        String lastName = userNode.hasNonNull("lastName") ? userNode.get("lastName").asText().trim() : "";
        if (lastName.isBlank()) {
            if (firstName.contains(" ")) {
                int spaceIdx = firstName.indexOf(' ');
                lastName = firstName.substring(spaceIdx + 1).trim();
                firstName = firstName.substring(0, spaceIdx).trim();
                userNode.put("firstName", firstName);
                userNode.put("lastName", lastName.isBlank() ? "Cliente" : lastName);
            } else {
                userNode.put("lastName", "Cliente");
            }
        }

        // Remover campos auxiliares del frontend no soportados por UserRepresentation de Keycloak
        userNode.remove("nombre");
        userNode.remove("dni");
        userNode.remove("telefono");
        userNode.remove("confirmPassword");
        userNode.remove("repassword");

        // Normalizar credenciales si vienen presentes
        if (userNode.has("credentials") && userNode.get("credentials").isArray()) {
            ArrayNode creds = (ArrayNode) userNode.get("credentials");
            for (JsonNode c : creds) {
                if (c.isObject()) {
                    ObjectNode credObj = (ObjectNode) c;
                    if (!credObj.has("type")) {
                        credObj.put("type", "password");
                    }
                    if (!credObj.has("temporary")) {
                        credObj.put("temporary", false);
                    }
                }
            }
        } else if (userNode.hasNonNull("password")) {
            // Soporte flexible si enviaron "password": "..." plano
            ArrayNode creds = userNode.putArray("credentials");
            ObjectNode pwdNode = creds.addObject();
            pwdNode.put("type", "password");
            pwdNode.put("value", userNode.get("password").asText());
            pwdNode.put("temporary", false);
            userNode.remove("password");
        }

        // Extraer rol opcional si fue enviado
        String rolOpcional = null;
        if (userNode.hasNonNull("rol")) {
            rolOpcional = userNode.get("rol").asText().trim().toUpperCase();
            userNode.remove("rol");
        } else if (userNode.hasNonNull("role")) {
            rolOpcional = userNode.get("role").asText().trim().toUpperCase();
            userNode.remove("role");
        }

        // 2. Obtener Token de Administrador de Keycloak
        String adminToken = obtenerAdminToken();
        if (adminToken == null || adminToken.isBlank()) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "No fue posible autenticarse con el servicio de identidad Keycloak"));
        }

        // 3. Crear usuario vía Keycloak Admin API
        List<String> baseUrls = List.of(primaryKeycloakUrl, fallbackKeycloakUrl);
        for (String baseUrl : baseUrls) {
            try {
                String createUrl = baseUrl + "/admin/realms/" + realm + "/users";
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(createUrl))
                        .header("Content-Type", "application/json")
                        .header("Authorization", "Bearer " + adminToken)
                        .timeout(Duration.ofSeconds(4))
                        .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(userNode), StandardCharsets.UTF_8))
                        .build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

                if (response.statusCode() == 201) {
                    // Extraer ID del usuario creado desde cabecera Location o por query
                    String userId = extraerUserId(response);
                    if (userId == null || userId.isBlank()) {
                        userId = buscarUserIdPorUsername(baseUrl, adminToken, username);
                    }

                    // Asignar rol: el solicitado o CLIENTE por defecto
                    String rolParaAsignar = (rolOpcional != null && !rolOpcional.isBlank()) ? rolOpcional : "CLIENTE";
                    if (userId != null) {
                        asignarRol(baseUrl, adminToken, userId, rolParaAsignar);
                    }

                    Map<String, Object> respBody = new LinkedHashMap<>();
                    respBody.put("mensaje", "Usuario registrado exitosamente en Keycloak");
                    respBody.put("username", username);
                    respBody.put("email", email);
                    respBody.put("rol", rolParaAsignar);
                    return ResponseEntity.status(HttpStatus.CREATED).body(respBody);
                } else if (response.statusCode() == 409) {
                    return ResponseEntity.status(HttpStatus.CONFLICT)
                            .body(Map.of("error", "El usuario o email ya se encuentra registrado en el sistema"));
                } else {
                    log.warn("Keycloak respondió con estado {} al crear usuario: {}", response.statusCode(), response.body());
                }
            } catch (Exception e) {
                log.debug("Error conectando a Keycloak en {}: {}", baseUrl, e.getMessage());
            }
        }

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Error interno al comunicarse con Keycloak"));
    }

    private String obtenerAdminToken() {
        List<String> baseUrls = List.of(primaryKeycloakUrl, fallbackKeycloakUrl);
        for (String baseUrl : baseUrls) {
            try {
                String tokenUrl = baseUrl + "/realms/master/protocol/openid-connect/token";
                String body = "grant_type=password"
                        + "&client_id=admin-cli"
                        + "&username=" + URLEncoder.encode(adminUser, StandardCharsets.UTF_8)
                        + "&password=" + URLEncoder.encode(adminPassword, StandardCharsets.UTF_8);

                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(tokenUrl))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .timeout(Duration.ofSeconds(3))
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() == 200) {
                    JsonNode node = objectMapper.readTree(response.body());
                    return node.has("access_token") ? node.get("access_token").asText() : null;
                }
            } catch (Exception e) {
                log.debug("No se pudo obtener token admin de {}: {}", baseUrl, e.getMessage());
            }
        }
        return null;
    }

    private String extraerUserId(HttpResponse<String> response) {
        Optional<String> location = response.headers().firstValue("Location");
        if (location.isPresent()) {
            String loc = location.get();
            int idx = loc.lastIndexOf('/');
            if (idx != -1 && idx < loc.length() - 1) {
                return loc.substring(idx + 1);
            }
        }
        return null;
    }

    private String buscarUserIdPorUsername(String baseUrl, String adminToken, String username) {
        try {
            String queryUrl = baseUrl + "/admin/realms/" + realm + "/users?username=" + URLEncoder.encode(username, StandardCharsets.UTF_8);
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(queryUrl))
                    .header("Authorization", "Bearer " + adminToken)
                    .timeout(Duration.ofSeconds(3))
                    .GET()
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                JsonNode array = objectMapper.readTree(response.body());
                if (array.isArray() && array.size() > 0) {
                    return array.get(0).has("id") ? array.get(0).get("id").asText() : null;
                }
            }
        } catch (Exception e) {
            log.debug("Error buscando usuario por username: {}", e.getMessage());
        }
        return null;
    }

    private void asignarRol(String baseUrl, String adminToken, String userId, String rolName) {
        try {
            // 1. Obtener representación del rol
            String roleUrl = baseUrl + "/admin/realms/" + realm + "/roles/" + URLEncoder.encode(rolName, StandardCharsets.UTF_8);
            HttpRequest roleReq = HttpRequest.newBuilder()
                    .uri(URI.create(roleUrl))
                    .header("Authorization", "Bearer " + adminToken)
                    .timeout(Duration.ofSeconds(3))
                    .GET()
                    .build();

            HttpResponse<String> roleResp = httpClient.send(roleReq, HttpResponse.BodyHandlers.ofString());
            if (roleResp.statusCode() == 200) {
                // 2. Asociar rol al usuario
                String mappingUrl = baseUrl + "/admin/realms/" + realm + "/users/" + userId + "/role-mappings/realm";
                String roleJson = "[" + roleResp.body() + "]";

                HttpRequest mappingReq = HttpRequest.newBuilder()
                        .uri(URI.create(mappingUrl))
                        .header("Content-Type", "application/json")
                        .header("Authorization", "Bearer " + adminToken)
                        .timeout(Duration.ofSeconds(3))
                        .POST(HttpRequest.BodyPublishers.ofString(roleJson, StandardCharsets.UTF_8))
                        .build();

                httpClient.send(mappingReq, HttpResponse.BodyHandlers.ofString());
                log.info("Rol {} asignado exitosamente al usuario {}", rolName, userId);
            }
        } catch (Exception e) {
            log.warn("No fue posible asignar el rol {} al usuario {}: {}", rolName, userId, e.getMessage());
        }
    }
}

