package kz.nurdos.spring_security.dto.authentication;

import kz.nurdos.spring_security.dto.GeneralResponseModel;

public class LoginResponse extends GeneralResponseModel {
    private final String jwtToken;

    public LoginResponse(boolean success, String message, String jwtToken) {
        super(success, message);
        this.jwtToken = jwtToken;
    }

    @Override
    public boolean getSuccess() {
        return super.getSuccess();
    }

    @Override
    public String getMessage() {
        return super.getMessage();
    }

    public String getJwtToken() {
        return jwtToken;
    }
}
