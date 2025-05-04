package kz.nurdos.spring_security.exception;

public class UnsuccessfulRegistrationException extends RuntimeException {
    public UnsuccessfulRegistrationException(String message) {
        super(message);
    }
}
