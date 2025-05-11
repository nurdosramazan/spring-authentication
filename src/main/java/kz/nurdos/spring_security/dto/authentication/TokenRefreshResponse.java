package kz.nurdos.spring_security.dto.authentication;

import kz.nurdos.spring_security.dto.ApiResponse;

public class TokenRefreshResponse extends ApiResponse {
    private final String accessToken;
    private final String refreshToken;

    public TokenRefreshResponse(boolean success, String message, String accessToken, String refreshToken) {
        super(success, message);
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }
}
