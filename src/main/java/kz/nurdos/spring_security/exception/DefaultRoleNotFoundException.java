package kz.nurdos.spring_security.exception;

public class DefaultRoleNotFoundException extends RuntimeException { //todo in global exception handler: careful with the return message
    public DefaultRoleNotFoundException(String message) {
        super(message);
    }
}
