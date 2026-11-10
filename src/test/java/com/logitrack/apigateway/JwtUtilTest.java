package com.logitrack.apigateway;

import com.logitrack.apigateway.util.JwtUtil;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JwtUtilTest {

    private JwtUtil jwtUtil;
    private static final String SECRET_KEY = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";

    @BeforeEach
    void setUp() {
        jwtUtil = new JwtUtil();
        ReflectionTestUtils.setField(jwtUtil, "secretKey", SECRET_KEY);
    }

    private String generateTestToken(String subject, List<String> roles, long expirationOffsetMs) {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        SecretKey key = Keys.hmacShaKeyFor(keyBytes);

        return Jwts.builder()
                .subject(subject)
                .claims(Map.of("roles", roles))
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expirationOffsetMs))
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    @Test
    void testValidToken() {
        String token = generateTestToken("admin@logitrack.com", List.of("ROLE_ADMIN"), 60000);

        assertTrue(jwtUtil.isTokenValid(token));
        assertEquals("admin@logitrack.com", jwtUtil.extractUsername(token));
        assertEquals(List.of("ROLE_ADMIN"), jwtUtil.extractRoles(token));
    }

    @Test
    void testExpiredToken() {
        String token = generateTestToken("user@logitrack.com", List.of("ROLE_CLIENTE"), -1000);

        assertFalse(jwtUtil.isTokenValid(token));
    }

    @Test
    void testTamperedToken() {
        String token = generateTestToken("user@logitrack.com", List.of("ROLE_CLIENTE"), 60000);
        String invalidToken = token.substring(0, token.length() - 5) + "abcde";

        assertFalse(jwtUtil.isTokenValid(invalidToken));
    }

    @Test
    void testKeycloakAsymmetricRs256TokenWithVendedorRole() throws Exception {
        // Generar par de claves RSA para simular Keycloak
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        String kid = "keycloak-test-key-id";
        jwtUtil.registerPublicKey(kid, keyPair.getPublic());

        String keycloakToken = Jwts.builder()
                .header().keyId(kid).and()
                .subject("d3b07384-d113-4d44-93be-123456789abc")
                .claim("preferred_username", "vendedor_carlos")
                .claim("email", "carlos@logitrack.com")
                .claim("realm_access", Map.of("roles", List.of("VENDEDOR", "default-roles-lazyhawk")))
                .claim("roles", List.of("VENDEDOR"))
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60000))
                .signWith(keyPair.getPrivate(), Jwts.SIG.RS256)
                .compact();

        assertTrue(jwtUtil.isTokenValid(keycloakToken));
        assertEquals("vendedor_carlos", jwtUtil.extractUsername(keycloakToken));
        List<String> roles = jwtUtil.extractRoles(keycloakToken);
        assertTrue(roles.contains("VENDEDOR"));
        assertTrue(roles.contains("default-roles-lazyhawk"));
    }

    @Test
    void testKeycloakRolesNestedInRealmAccess() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        jwtUtil.setDefaultRsaPublicKey(keyPair.getPublic());

        String token = Jwts.builder()
                .subject("user-uuid")
                .claim("preferred_username", "repartidor_ana")
                .claim("realm_access", Map.of("roles", List.of("REPARTIDOR")))
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 60000))
                .signWith(keyPair.getPrivate(), Jwts.SIG.RS256)
                .compact();

        assertTrue(jwtUtil.isTokenValid(token));
        assertEquals("repartidor_ana", jwtUtil.extractUsername(token));
        assertEquals(List.of("REPARTIDOR"), jwtUtil.extractRoles(token));
    }
}
