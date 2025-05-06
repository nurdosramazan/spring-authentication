package kz.nurdos.spring_security.exception;

import kz.nurdos.spring_security.dto.GeneralResponseModel;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(UnsuccessfulRegistrationException.class)
    public ResponseEntity<GeneralResponseModel> handleUnsuccessfulRegistration(UnsuccessfulRegistrationException e) {
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(new GeneralResponseModel(false, e.getMessage()));
    }

    @ExceptionHandler(UnsuccessfulLoginException.class)
    public ResponseEntity<GeneralResponseModel> handleUnsuccessfulLogin(UnsuccessfulLoginException exception) {
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(new GeneralResponseModel(false, exception.getMessage()));
    }
}
