package kz.nurdos.spring_security.dto.authentication;

import kz.nurdos.spring_security.dto.ApiResponse;

public class LoginResponse extends ApiResponse {
    private final String accessToken;
    private final String refreshToken;

    public LoginResponse(boolean success, String message, String accessToken, String refreshToken) {
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
