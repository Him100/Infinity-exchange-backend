package com.infinityexchange.infinityExchange.config;

import com.infinityexchange.infinityExchange.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, 
                                   @NonNull HttpServletResponse response, 
                                   @NonNull FilterChain filterChain) throws ServletException, IOException {
        
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String username;

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        jwt = authHeader.substring(7);
        
        try {
            // Use extractUsername instead of getUsernameFromToken
            username = jwtService.extractUsername(jwt);

            if (username != null) {
                System.out.println("DEBUG: Extracted username from JWT: '" + username + "'");

                // Check if authentication is already set up
                Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();
                System.out.println("DEBUG: Existing authentication: " + existingAuth);

                if (existingAuth == null || !existingAuth.isAuthenticated()) {
                    System.out.println("DEBUG: Setting up new authentication context");

                    // Use isTokenValid instead of returning Claims as boolean
                    if (jwtService.isTokenValid(jwt)) {
                        System.out.println("DEBUG: JWT token is valid");

                        UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
                        System.out.println("DEBUG: Loaded user details for: " + username);

                        UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities()
                            );

                        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authToken);
                        System.out.println("DEBUG: Authentication context set successfully");
                    } else {
                        System.out.println("DEBUG: JWT token is invalid");
                    }
                } else {
                    System.out.println("DEBUG: Authentication already exists: " + existingAuth.getName());
                }
            } else {
                System.out.println("DEBUG: Could not extract username from JWT");
            }
        } catch (Exception e) {
            logger.error("JWT token validation failed", e);
            System.out.println("DEBUG: JWT validation exception: " + e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
}