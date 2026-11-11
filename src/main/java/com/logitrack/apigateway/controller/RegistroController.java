package com.logitrack.apigateway.controller;

import com.logitrack.apigateway.service.KeycloakRegistrationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class RegistroController {

    private final KeycloakRegistrationService registrationService;

    public RegistroController(KeycloakRegistrationService registrationService) {
        this.registrationService = registrationService;
    }

    @PostMapping("/registro")
    public Mono<ResponseEntity<Map<String, Object>>> registrar(@RequestBody Map<String, Object> payload) {
        return Mono.fromCallable(() -> registrationService.registrarUsuario(payload));
    }
}

