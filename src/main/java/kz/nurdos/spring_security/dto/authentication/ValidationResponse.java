package kz.nurdos.spring_security.dto.authentication;

import kz.nurdos.spring_security.dto.GeneralResponseModel;

import java.util.List;

public class ValidationResponse extends GeneralResponseModel {
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
