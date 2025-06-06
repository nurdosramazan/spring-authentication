package kz.nurdos.spring_security.dto.authentication;

import kz.nurdos.spring_security.dto.ApiResponse;

import java.util.List;

public class ValidationResponse extends ApiResponse {
    private final List<InvalidError> errors;
    public ValidationResponse(boolean success, String message, List<InvalidError> errors) {
        super(success, message);
        this.errors = errors;
    }

    public List<InvalidError> getErrors() {
        return errors;
    }

    public record InvalidError(String field, String message) {}
}
