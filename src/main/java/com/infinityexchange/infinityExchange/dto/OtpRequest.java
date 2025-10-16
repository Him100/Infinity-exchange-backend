package com.infinityexchange.infinityExchange.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder

public class OtpRequest {
    private String userId;
    private String password;
    private String otp;
}