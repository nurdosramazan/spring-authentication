package kz.nurdos.spring_security.controllers;

import kz.nurdos.spring_security.dto.GeneralResponseModel;
import kz.nurdos.spring_security.dto.authentication.LoginRequest;
import kz.nurdos.spring_security.dto.authentication.LoginResponse;
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
    public ResponseEntity<GeneralResponseModel> login(@RequestBody LoginRequest loginRequest) {
        String result = authenticationService.login(loginRequest);

        return ResponseEntity
                .status(HttpStatus.OK)
                .body(new LoginResponse(true, "User logged in successfully", result));
    }

    @PostMapping("/register")
    public ResponseEntity<GeneralResponseModel> register(@RequestBody UserRegistrationRequest request) {
        authenticationService.registerUser(request);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(new GeneralResponseModel(true, "User successfully created"));
    }
}
