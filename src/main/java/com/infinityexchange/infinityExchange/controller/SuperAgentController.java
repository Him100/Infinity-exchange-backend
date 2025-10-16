package com.infinityexchange.infinityExchange.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/superagent")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:8080")
@PreAuthorize("hasRole('SUPERAGENT')")
public class SuperAgentController {
    @GetMapping("/dashboard")
    public ResponseEntity<String> getDashboard() {
        return ResponseEntity.ok("SuperAgent Dashboard");
    }
}