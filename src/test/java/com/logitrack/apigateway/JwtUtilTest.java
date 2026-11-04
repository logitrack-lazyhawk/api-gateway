package com.logitrack.apigateway;

import com.logitrack.apigateway.util.JwtUtil;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.SecretKey;
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
}

