package kz.nurdos.spring_security.dto.authentication;

import jakarta.validation.constraints.NotBlank;

public class TokenRefreshRequest {
    @NotBlank(message = "Refresh token is blank")
    private final String refreshToken;

    public TokenRefreshRequest(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }
}
