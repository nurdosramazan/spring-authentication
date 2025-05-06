package kz.nurdos.spring_security.exception;

public class UnsuccessfulLoginException extends RuntimeException {
    public UnsuccessfulLoginException(String message) {
        super(message);
    }
}
