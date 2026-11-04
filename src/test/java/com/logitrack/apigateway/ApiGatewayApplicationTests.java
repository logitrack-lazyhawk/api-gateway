package com.logitrack.apigateway;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(properties = "security.jwt.secret-key=404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970")
class ApiGatewayApplicationTests {

    @Test
    void contextLoads() {
    }

}
