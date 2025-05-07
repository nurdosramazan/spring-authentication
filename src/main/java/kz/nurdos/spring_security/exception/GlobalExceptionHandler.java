package kz.nurdos.spring_security.exception;

import kz.nurdos.spring_security.dto.GeneralResponseModel;
import kz.nurdos.spring_security.dto.authentication.ValidationResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.List;

@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler({UnsuccessfulRegistrationException.class, UnsuccessfulLoginException.class})
    public ResponseEntity<GeneralResponseModel> handleUnsuccessfulAuthorization(RuntimeException exception) {
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(new GeneralResponseModel(false, exception.getMessage()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<GeneralResponseModel> handleMethodArgumentNotValid(MethodArgumentNotValidException exception) {
        List<ValidationResponse.InvalidError> fieldErrors = exception.getBindingResult().getFieldErrors()
                .stream()
                .map(error -> new ValidationResponse.InvalidError(
                        error.getField(), error.getDefaultMessage()
                ))
                .toList();

        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(new ValidationResponse(false, "Invalid data provided.", fieldErrors));

    }
}
