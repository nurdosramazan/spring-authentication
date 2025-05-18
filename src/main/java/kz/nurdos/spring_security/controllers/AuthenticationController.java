package kz.nurdos.spring_security.controllers;

import jakarta.servlet.http.HttpServletRequest;
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
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
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
    public ResponseEntity<ApiResponse> loginUser(@RequestBody @Valid LoginRequest loginRequest, HttpServletRequest httpServletRequest) {
        LoginResponse loginResponse = authenticationService.loginUser(loginRequest, httpServletRequest);

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
    public ResponseEntity<ApiResponse> refreshToken(@RequestBody @Valid TokenRefreshRequest tokenRefreshRequest, HttpServletRequest httpServletRequest) {
        TokenRefreshResponse tokenRefreshResponse = authenticationService.refreshToken(tokenRefreshRequest, httpServletRequest);
        return ResponseEntity
                .status(HttpStatus.OK)
                .body(tokenRefreshResponse);
    }

    @GetMapping("/sessions")
    public ResponseEntity<ApiResponse> getActiveSessions(Authentication authentication,
                                                         @RequestHeader(name = "X-Current-Refresh-Token")
                                                         String currentRefreshTokenHeader) {
        //Point A: Implement current request's refresh token if we want to mark "isCurrentSession"
        ApiResponse sessionsResponse = authenticationService.getActiveSessions(authentication, currentRefreshTokenHeader);

        return ResponseEntity
                .status(HttpStatus.OK)
                .body(sessionsResponse);
    }

    @DeleteMapping("/sessions/{tokenToRevoke}")
    public ResponseEntity<ApiResponse> revokeSession(@PathVariable String tokenToRevoke,
                                                     Authentication authentication) {
        ApiResponse revokeResponse = authenticationService.revokeRefreshToken(tokenToRevoke, authentication);

        return ResponseEntity
                .status(HttpStatus.OK)
                .body(revokeResponse);
    }

    @PostMapping("/sessions/revoke-others")
    public ResponseEntity<ApiResponse> revokeOtherSessions(@RequestBody TokenRefreshRequest tokenRefreshRequest,
                                                           Authentication authentication) {
        ApiResponse revokeOthersResponse =
                authenticationService.revokeOtherSessions(tokenRefreshRequest, authentication);

        return ResponseEntity
                .status(HttpStatus.OK)
                .body(revokeOthersResponse);
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse> logoutUser(@RequestBody @Valid TokenRefreshRequest request) {
        ApiResponse logoutResponse = authenticationService.logoutUser(request.getRefreshToken());
        return ResponseEntity
                .status(HttpStatus.OK)
                .body(logoutResponse);
    }
}
