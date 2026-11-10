package com.logitrack.apigateway.filter;

import com.logitrack.apigateway.util.JwtUtil;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.reactive.CorsUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;

/**
 * Filtro global reactivo para validación centralizada de tokens JWT y control de acceso RBAC.
 * Soporta tokens Keycloak (RS256) y tradicionales (HS256) con inyección de cabeceras de contexto downstream.
 */
@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private final JwtUtil jwtUtil;

    // Rutas públicas que no requieren token JWT
    private static final Set<String> PUBLIC_PREFIXES = Set.of(
            "/api/auth/",
            "/actuator"
    );

    public JwtAuthenticationFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();

        // 0. Omitir validación en peticiones preflight CORS u OPTIONS
        if (CorsUtils.isPreFlightRequest(request) || request.getMethod() == HttpMethod.OPTIONS) {
            return chain.filter(exchange);
        }

        String path = request.getPath().value();

        // 1. Omitir validación en rutas públicas
        if (isPublicPath(path)) {
            return chain.filter(exchange);
        }

        // 2. Interceptar cabecera Authorization
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return onError(exchange, HttpStatus.UNAUTHORIZED, "Token de autenticacion no proporcionado");
        }

        String token = authHeader.substring(7).trim();
        if (token.isEmpty()) {
            return onError(exchange, HttpStatus.UNAUTHORIZED, "Token de autenticacion vacio");
        }

        // 3. Validar firma y expiración del JWT
        if (!jwtUtil.isTokenValid(token)) {
            return onError(exchange, HttpStatus.UNAUTHORIZED, "Token de autenticacion invalido o expirado");
        }

        // 4. Extraer roles y validar permisos de acceso por ruta (RBAC)
        List<String> roles = jwtUtil.extractRoles(token);
        if (!isAuthorized(path, roles)) {
            return onError(exchange, HttpStatus.FORBIDDEN, "Acceso denegado: permisos insuficientes para el recurso solicitado");
        }

        // 5. Propagar identidad y roles en cabeceras downstream
        String username = jwtUtil.extractUsername(token);
        ServerHttpRequest mutatedRequest = request.mutate()
                .header("X-Auth-User", username != null ? username : "")
                .header("X-Auth-Roles", String.join(",", roles))
                .build();

        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    private boolean isPublicPath(String path) {
        return PUBLIC_PREFIXES.stream().anyMatch(path::startsWith);
    }

    private boolean isAuthorized(String path, List<String> roles) {
        boolean isAdmin = hasRole(roles, "ADMIN");
        boolean isRepartidor = hasRole(roles, "REPARTIDOR");
        boolean isCliente = hasRole(roles, "CLIENTE");
        boolean isVendedor = hasRole(roles, "VENDEDOR");

        // Administrador tiene acceso total a todas las rutas
        if (isAdmin) {
            return true;
        }

        // Rutas de repartidores: solo ADMIN y REPARTIDOR
        if (path.startsWith("/api/v1/repartidores")) {
            return isRepartidor;
        }

        // Rutas de clientes: solo ADMIN y CLIENTE
        if (path.startsWith("/api/v1/clientes")) {
            return isCliente;
        }

        // Rutas de envíos: CLIENTE, REPARTIDOR y VENDEDOR
        if (path.startsWith("/api/v1/envios")) {
            return isCliente || isRepartidor || isVendedor;
        }

        // Rutas de productos o catálogo e-commerce: VENDEDOR y ADMIN
        if (path.startsWith("/api/v1/productos") || path.startsWith("/api/v1/commerce")) {
            return isVendedor;
        }

        return false;
    }

    private boolean hasRole(List<String> roles, String targetRole) {
        return roles.stream().anyMatch(r ->
                r.equalsIgnoreCase(targetRole) || r.equalsIgnoreCase("ROLE_" + targetRole)
        );
    }

    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus status, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        byte[] bytes = String.format("{\"status\":%d,\"error\":\"%s\"}", status.value(), message)
                .getBytes(StandardCharsets.UTF_8);
        DataBuffer buffer = response.bufferFactory().wrap(bytes);
        return response.writeWith(Mono.just(buffer));
    }

    @Override
    public int getOrder() {
        return -100; // Prioridad alta para validar antes de enrutar
    }
}
