package kz.nurdos.spring_security.exception;

import kz.nurdos.spring_security.dto.ApiResponse;
import kz.nurdos.spring_security.dto.authentication.ValidationResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.List;

/*
handleAllExceptions(Exception exception):
This is your crucial fallback handler.
CRITICAL SECURITY/DEBUGGING POINT: You are currently not logging the exception itself. In a production environment,
if an unexpected error occurs, this log line is your primary way of knowing what actually went wrong. Without it,
you'll just know "an error occurred" but have no details to diagnose it.

Action: Add logging using SLF4J or your preferred logging framework. Log exception.getMessage() and the full stack
trace: logger.error("An unexpected error occurred: ", exception);
 */

@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(UnsuccessfulRegistrationException.class)
    public ResponseEntity<ApiResponse> handleUnsuccessfulRegistration(UnsuccessfulRegistrationException exception) {
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(new ApiResponse(false, exception.getMessage()));
    }

    @ExceptionHandler(UnsuccessfulLoginException.class)
    public ResponseEntity<ApiResponse> handleUnsuccessfulLogin(UnsuccessfulLoginException exception) {
        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(new ApiResponse(false, exception.getMessage()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse> handleMethodArgumentNotValid(MethodArgumentNotValidException exception) {
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

    @ExceptionHandler(RefreshTokenExpiredException.class)
    public ResponseEntity<ApiResponse> handleRefreshTokenExpired(RefreshTokenExpiredException exception) {
        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(new ApiResponse(false, exception.getMessage()));
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<ApiResponse> handleUsernameNotFound(UsernameNotFoundException exception) {
        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(new ApiResponse(false, exception.getMessage()));
    }

    @ExceptionHandler(UnsuccessfulRefreshTokenException.class)
    public ResponseEntity<ApiResponse> handleUnsuccessfulRefreshToken(UnsuccessfulRefreshTokenException exception) {
        return ResponseEntity
                .status(401)
                .body(new ApiResponse(false, exception.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse> handleAllExceptions(Exception exception) {
        //todo:
        // CRITICAL: Log the exception here so you know what happened!
        // private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);
        // logger.error("Unhandled exception caught: ", exception);
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ApiResponse(false, "An unexpected error occurred, please contact support."));
    }
}
