package com.logitrack.apigateway.filter;

import com.logitrack.apigateway.util.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTest {

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private GatewayFilterChain chain;

    private JwtAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        filter = new JwtAuthenticationFilter(jwtUtil);
        lenient().when(chain.filter(any())).thenReturn(Mono.empty());
    }

    @Test
    void testPublicPathBypassesFilter() {
        MockServerHttpRequest request = MockServerHttpRequest
                .post("/api/auth/login")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        filter.filter(exchange, chain).block();

        verify(chain).filter(exchange);
        verifyNoInteractions(jwtUtil);
    }

    @Test
    void testOptionsRequestBypassesFilter() {
        MockServerHttpRequest request = MockServerHttpRequest
                .method(HttpMethod.OPTIONS, "/api/v1/envios")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        filter.filter(exchange, chain).block();

        verify(chain).filter(exchange);
        verifyNoInteractions(jwtUtil);
    }

    @Test
    void testMissingAuthHeaderReturns401() {
        MockServerHttpRequest request = MockServerHttpRequest
                .get("/api/v1/envios")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        filter.filter(exchange, chain).block();

        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
        verifyNoInteractions(chain);
    }

    @Test
    void testInvalidTokenReturns401() {
        MockServerHttpRequest request = MockServerHttpRequest
                .get("/api/v1/envios")
                .header(HttpHeaders.AUTHORIZATION, "Bearer invalid-token")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        when(jwtUtil.isTokenValid("invalid-token")).thenReturn(false);

        filter.filter(exchange, chain).block();

        assertEquals(HttpStatus.UNAUTHORIZED, exchange.getResponse().getStatusCode());
        verifyNoInteractions(chain);
    }

    @Test
    void testForbiddenRoleReturns403() {
        MockServerHttpRequest request = MockServerHttpRequest
                .get("/api/v1/repartidores/123")
                .header(HttpHeaders.AUTHORIZATION, "Bearer valid-token")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        when(jwtUtil.isTokenValid("valid-token")).thenReturn(true);
        when(jwtUtil.extractRoles("valid-token")).thenReturn(List.of("CLIENTE"));

        filter.filter(exchange, chain).block();

        assertEquals(HttpStatus.FORBIDDEN, exchange.getResponse().getStatusCode());
        verifyNoInteractions(chain);
    }

    @Test
    void testClienteConsultandoMisEnviosSucceeds() {
        MockServerHttpRequest request = MockServerHttpRequest
                .get("/api/v1/envios/mis-envios")
                .header(HttpHeaders.AUTHORIZATION, "Bearer valid-token")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        when(jwtUtil.isTokenValid("valid-token")).thenReturn(true);
        when(jwtUtil.extractRoles("valid-token")).thenReturn(List.of("CLIENTE"));
        when(jwtUtil.extractUsername("valid-token")).thenReturn("cliente@logitrack.com");

        filter.filter(exchange, chain).block();

        verify(chain).filter(argThat(ex -> {
            HttpHeaders headers = ex.getRequest().getHeaders();
            return "cliente@logitrack.com".equals(headers.getFirst("X-Auth-User")) &&
                    "CLIENTE".equals(headers.getFirst("X-Auth-Roles"));
        }));
    }

    @Test
    void testClienteConsultandoTrackingSucceeds() {
        MockServerHttpRequest request = MockServerHttpRequest
                .get("/api/v1/envios/mis-envios/tracking/ENV-12345")
                .header(HttpHeaders.AUTHORIZATION, "Bearer valid-token")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        when(jwtUtil.isTokenValid("valid-token")).thenReturn(true);
        when(jwtUtil.extractRoles("valid-token")).thenReturn(List.of("CLIENTE"));
        when(jwtUtil.extractUsername("valid-token")).thenReturn("cliente@logitrack.com");

        filter.filter(exchange, chain).block();

        verify(chain).filter(argThat(ex -> {
            HttpHeaders headers = ex.getRequest().getHeaders();
            return "cliente@logitrack.com".equals(headers.getFirst("X-Auth-User")) &&
                    "CLIENTE".equals(headers.getFirst("X-Auth-Roles"));
        }));
    }

    @Test
    void testClienteIntentandoCrearEnvioDirectoReturns403() {
        MockServerHttpRequest request = MockServerHttpRequest
                .post("/api/v1/envios")
                .header(HttpHeaders.AUTHORIZATION, "Bearer valid-token")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        when(jwtUtil.isTokenValid("valid-token")).thenReturn(true);
        when(jwtUtil.extractRoles("valid-token")).thenReturn(List.of("CLIENTE"));

        filter.filter(exchange, chain).block();

        assertEquals(HttpStatus.FORBIDDEN, exchange.getResponse().getStatusCode());
        verifyNoInteractions(chain);
    }

    @Test
    void testVendedorAccessingProductsSucceedsAndInjectsHeaders() {
        MockServerHttpRequest request = MockServerHttpRequest
                .post("/api/v1/productos")
                .header(HttpHeaders.AUTHORIZATION, "Bearer valid-vendedor-token")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        when(jwtUtil.isTokenValid("valid-vendedor-token")).thenReturn(true);
        when(jwtUtil.extractRoles("valid-vendedor-token")).thenReturn(List.of("VENDEDOR"));
        when(jwtUtil.extractUsername("valid-vendedor-token")).thenReturn("vendedor_miguel");

        filter.filter(exchange, chain).block();

        verify(chain).filter(argThat(ex -> {
            HttpHeaders headers = ex.getRequest().getHeaders();
            return "vendedor_miguel".equals(headers.getFirst("X-Auth-User")) &&
                    "VENDEDOR".equals(headers.getFirst("X-Auth-Roles"));
        }));
    }

    @Test
    void testAdminAccessAnyRouteSucceeds() {
        MockServerHttpRequest request = MockServerHttpRequest
                .get("/api/v1/repartidores/disponibles")
                .header(HttpHeaders.AUTHORIZATION, "Bearer admin-token")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        when(jwtUtil.isTokenValid("admin-token")).thenReturn(true);
        when(jwtUtil.extractRoles("admin-token")).thenReturn(List.of("ROLE_ADMIN"));
        when(jwtUtil.extractUsername("admin-token")).thenReturn("admin");

        filter.filter(exchange, chain).block();

        verify(chain).filter(argThat(ex -> {
            HttpHeaders headers = ex.getRequest().getHeaders();
            return "admin".equals(headers.getFirst("X-Auth-User")) &&
                    "ROLE_ADMIN".equals(headers.getFirst("X-Auth-Roles"));
        }));
    }

    @Test
    void testClienteAccessingProductsCatalogViaGetSucceeds() {
        MockServerHttpRequest request = MockServerHttpRequest
                .get("/api/v1/productos")
                .header(HttpHeaders.AUTHORIZATION, "Bearer valid-token")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        when(jwtUtil.isTokenValid("valid-token")).thenReturn(true);
        when(jwtUtil.extractRoles("valid-token")).thenReturn(List.of("CLIENTE"));
        when(jwtUtil.extractUsername("valid-token")).thenReturn("cliente@logitrack.com");

        filter.filter(exchange, chain).block();

        verify(chain).filter(argThat(ex -> {
            HttpHeaders headers = ex.getRequest().getHeaders();
            return "cliente@logitrack.com".equals(headers.getFirst("X-Auth-User")) &&
                    "CLIENTE".equals(headers.getFirst("X-Auth-Roles"));
        }));
    }

    @Test
    void testClienteTryingToModifyProductsReturns403() {
        MockServerHttpRequest request = MockServerHttpRequest
                .post("/api/v1/productos")
                .header(HttpHeaders.AUTHORIZATION, "Bearer valid-token")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        when(jwtUtil.isTokenValid("valid-token")).thenReturn(true);
        when(jwtUtil.extractRoles("valid-token")).thenReturn(List.of("CLIENTE"));

        filter.filter(exchange, chain).block();

        assertEquals(HttpStatus.FORBIDDEN, exchange.getResponse().getStatusCode());
        verifyNoInteractions(chain);
    }

    @Test
    void testClienteAccessingCarritoSucceeds() {
        MockServerHttpRequest request = MockServerHttpRequest
                .get("/api/v1/carritos/usr-123")
                .header(HttpHeaders.AUTHORIZATION, "Bearer valid-token")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);

        when(jwtUtil.isTokenValid("valid-token")).thenReturn(true);
        when(jwtUtil.extractRoles("valid-token")).thenReturn(List.of("CLIENTE"));
        when(jwtUtil.extractUsername("valid-token")).thenReturn("cliente@logitrack.com");

        filter.filter(exchange, chain).block();

        verify(chain).filter(argThat(ex -> {
            HttpHeaders headers = ex.getRequest().getHeaders();
            return "cliente@logitrack.com".equals(headers.getFirst("X-Auth-User")) &&
                    "CLIENTE".equals(headers.getFirst("X-Auth-Roles"));
        }));
    }
}
