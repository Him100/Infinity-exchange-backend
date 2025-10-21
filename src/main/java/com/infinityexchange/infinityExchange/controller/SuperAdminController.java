package com.infinityexchange.infinityExchange.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/superadmin")
@RequiredArgsConstructor
@CrossOrigin(
    origins = {"http://localhost:5173", "http://localhost:3000", "http://localhost:4173", "http://localhost:8080", "http://localhost:8085", "http://192.168.43.33:8080"},
    allowCredentials = "true"
)
@PreAuthorize("hasRole('SUPERADMIN')")
public class SuperAdminController {

    @GetMapping("/dashboard")
    public ResponseEntity<String> getDashboard() {
        return ResponseEntity.ok("SuperAdmin Dashboard - Full system access");
    }

    @GetMapping("/users")
    public ResponseEntity<String> getAllUsers() {
        return ResponseEntity.ok("List of all users in the system");
    }

    @PostMapping("/users")
    public ResponseEntity<String> createUser() {
        return ResponseEntity.ok("Create new user");
    }
}