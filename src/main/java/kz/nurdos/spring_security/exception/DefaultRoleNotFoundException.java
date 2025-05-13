package kz.nurdos.spring_security.exception;

import kz.nurdos.spring_security.dto.authentication.UserRegistrationRequest;

public class DefaultRoleNotFoundException extends RuntimeException { //todo in global exception handler: careful with the return message
    private final UserRegistrationRequest request;
    public DefaultRoleNotFoundException(String message, UserRegistrationRequest request) {
        super(message);
        this.request = request;
    }

    public UserRegistrationRequest getRequest() {
        return request;
    }
}
