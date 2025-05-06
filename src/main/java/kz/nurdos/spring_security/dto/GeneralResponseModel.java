package kz.nurdos.spring_security.dto;

public class GeneralResponseModel {
    private final boolean success;
    private final String message;

    public GeneralResponseModel(boolean success, String message) {
        this.success = success;
        this.message = message;
    }

    public boolean getSuccess() {
        return success;
    }

    public String getMessage() {
        return message;
    }
}
