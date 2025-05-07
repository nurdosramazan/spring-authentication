package kz.nurdos.spring_security.dto.authentication;

import kz.nurdos.spring_security.dto.GeneralResponseModel;

public class LoginResponse extends GeneralResponseModel {
    private final String token;

    public LoginResponse(boolean success, String message, String token) {
        super(success, message);
        this.token = token;
    }

    @Override
    public boolean getSuccess() {
        return super.getSuccess();
    }

    @Override
    public String getMessage() {
        return super.getMessage();
    }

    public String getToken() {
        return token;
    }
}
