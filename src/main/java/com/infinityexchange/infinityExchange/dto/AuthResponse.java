package com.infinityexchange.infinityExchange.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.infinityexchange.infinityExchange.entity.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthResponse {
    private String token;
    private User user;
    private String message;
    private String error;
    private boolean requiresOtp;
}