package com.logitrack.apigateway.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.JwkSet;
import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.PublicKey;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Utilidad para validación, parsing y extracción de información de tokens JWT.
 * Soporta tokens simétricos (HS256) y asimétricos emitidos por Keycloak (RS256 / JWKS).
 */
@Component
public class JwtUtil {

    private static final Logger log = LoggerFactory.getLogger(JwtUtil.class);

    @Value("${security.jwt.secret-key:404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970}")
    private String secretKey;

    @Value("${security.jwt.jwk-set-uri:http://localhost:8082/realms/lazyhawk/protocol/openid-connect/certs}")
    private String jwkSetUri;

    private final Map<String, PublicKey> keyCache = new ConcurrentHashMap<>();
    private PublicKey defaultRsaPublicKey;
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3))
            .build();

    public Claims extractAllClaims(String token) {
        return Jwts.parser()
                .keyLocator(header -> {
                    String alg = header.getAlgorithm();
                    if (alg != null && alg.startsWith("RS")) {
                        Object kidObj = header.get("kid");
                        String kid = kidObj != null ? kidObj.toString() : null;
                        PublicKey key = resolveRsaPublicKey(kid);
                        if (key != null) {
                            return key;
                        }
                    }
                    return getSigningKey();
                })
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String extractUsername(String token) {
        Claims claims = extractAllClaims(token);
        String preferredUsername = claims.get("preferred_username", String.class);
        if (preferredUsername != null && !preferredUsername.isBlank()) {
            return preferredUsername;
        }
        return claims.getSubject();
    }

    @SuppressWarnings("unchecked")
    public List<String> extractRoles(String token) {
        Set<String> collectedRoles = new LinkedHashSet<>();
        try {
            Claims claims = extractAllClaims(token);

            // 1. Claim raíz 'roles' (definido por el Realm Mapper de Keycloak o tokens personalizados)
            Object rolesObj = claims.get("roles");
            if (rolesObj instanceof List<?> list) {
                list.stream().map(Object::toString).forEach(collectedRoles::add);
            } else if (rolesObj instanceof String roleStr) {
                Arrays.stream(roleStr.split(",")).map(String::trim).forEach(collectedRoles::add);
            }

            // 2. Estructura estándar Keycloak: realm_access.roles
            Object realmAccessObj = claims.get("realm_access");
            if (realmAccessObj instanceof Map<?, ?> realmAccess) {
                Object realmRoles = realmAccess.get("roles");
                if (realmRoles instanceof List<?> list) {
                    list.stream().map(Object::toString).forEach(collectedRoles::add);
                }
            }

            // 3. Estructura estándar Keycloak: resource_access.<client>.roles
            Object resourceAccessObj = claims.get("resource_access");
            if (resourceAccessObj instanceof Map<?, ?> resourceAccess) {
                for (Object clientObj : resourceAccess.values()) {
                    if (clientObj instanceof Map<?, ?> clientMap) {
                        Object clientRoles = clientMap.get("roles");
                        if (clientRoles instanceof List<?> list) {
                            list.stream().map(Object::toString).forEach(collectedRoles::add);
                        }
                    }
                }
            }

            // 4. Fallback por si viniera bajo claim singular 'rol' o 'role'
            Object singleRole = claims.get("rol");
            if (singleRole == null) {
                singleRole = claims.get("role");
            }
            if (singleRole != null) {
                collectedRoles.add(singleRole.toString());
            }
        } catch (Exception e) {
            log.debug("Error extrayendo roles del token JWT: {}", e.getMessage());
        }
        return new ArrayList<>(collectedRoles);
    }

    public boolean isTokenValid(String token) {
        try {
            Claims claims = extractAllClaims(token);
            return claims.getExpiration() != null && !claims.getExpiration().before(new Date());
        } catch (JwtException | IllegalArgumentException e) {
            log.debug("Token JWT no valido: {}", e.getMessage());
            return false;
        }
    }

    public void registerPublicKey(String kid, PublicKey publicKey) {
        if (kid != null && publicKey != null) {
            keyCache.put(kid, publicKey);
        }
    }

    public void setDefaultRsaPublicKey(PublicKey defaultRsaPublicKey) {
        this.defaultRsaPublicKey = defaultRsaPublicKey;
    }

    private PublicKey resolveRsaPublicKey(String kid) {
        if (kid != null && keyCache.containsKey(kid)) {
            return keyCache.get(kid);
        }

        // Intento de refresco contra el endpoint JWKS de Keycloak
        fetchJwkKeys();

        if (kid != null && keyCache.containsKey(kid)) {
            return keyCache.get(kid);
        }

        return defaultRsaPublicKey;
    }

    private synchronized void fetchJwkKeys() {
        List<String> urisToTry = new ArrayList<>();
        if (jwkSetUri != null && !jwkSetUri.isBlank()) {
            urisToTry.add(jwkSetUri);
        }
        if (!urisToTry.contains("http://keycloak:8080/realms/lazyhawk/protocol/openid-connect/certs")) {
            urisToTry.add("http://keycloak:8080/realms/lazyhawk/protocol/openid-connect/certs");
        }
        if (!urisToTry.contains("http://localhost:8082/realms/lazyhawk/protocol/openid-connect/certs")) {
            urisToTry.add("http://localhost:8082/realms/lazyhawk/protocol/openid-connect/certs");
        }

        for (String uri : urisToTry) {
            try {
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(uri))
                        .timeout(Duration.ofSeconds(2))
                        .GET()
                        .build();

                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() == 200) {
                    JwkSet jwkSet = Jwks.setParser().build().parse(response.body());
                    for (Jwk<?> jwk : jwkSet.getKeys()) {
                        if (jwk.getId() != null && jwk.toKey() instanceof PublicKey pk) {
                            keyCache.put(jwk.getId(), pk);
                        }
                    }
                    log.info("JWKS cargado exitosamente desde {}", uri);
                    return;
                }
            } catch (Exception e) {
                log.debug("No fue posible consultar endpoint JWKS en {}: {}", uri, e.getMessage());
            }
        }
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
