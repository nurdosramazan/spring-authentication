package kz.nurdos.spring_security.exception;

public class UnsuccessfulRefreshTokenException extends RuntimeException {
    public UnsuccessfulRefreshTokenException(String message) {
        super(message);
    }
}
