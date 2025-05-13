package kz.nurdos.spring_security.controllers;

import jakarta.validation.Valid;
import kz.nurdos.spring_security.dto.ApiResponse;
import kz.nurdos.spring_security.dto.authentication.LoginRequest;
import kz.nurdos.spring_security.dto.authentication.LoginResponse;
import kz.nurdos.spring_security.dto.authentication.TokenRefreshRequest;
import kz.nurdos.spring_security.dto.authentication.TokenRefreshResponse;
import kz.nurdos.spring_security.dto.authentication.UserRegistrationRequest;
import kz.nurdos.spring_security.service.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthenticationController {
    private final AuthenticationService authenticationService;

    @Autowired
    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse> loginUser(@RequestBody @Valid LoginRequest loginRequest) {
        LoginResponse loginResponse = authenticationService.loginUser(loginRequest);

        return ResponseEntity
                .status(HttpStatus.OK)
                .body(loginResponse);
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse> register(@RequestBody @Valid UserRegistrationRequest request) {
        ApiResponse registerResponse = authenticationService.registerUser(request);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(registerResponse);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<ApiResponse> refreshToken(@RequestBody @Valid TokenRefreshRequest request) {
        TokenRefreshResponse response = authenticationService.refreshToken(request.getRefreshToken());
        return ResponseEntity
                .status(HttpStatus.OK)
                .body(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse> logoutUser(@RequestBody @Valid TokenRefreshRequest request) {
        ApiResponse response = authenticationService.logoutUser(request.getRefreshToken());
        return ResponseEntity
                .status(HttpStatus.OK)
                .body(response);
    }
}
