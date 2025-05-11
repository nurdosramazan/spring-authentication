package kz.nurdos.spring_security.service;

import jakarta.transaction.Transactional;
import kz.nurdos.spring_security.exception.UnsuccessfulRefreshTokenException;
import kz.nurdos.spring_security.mappers.EntityMapper;
import kz.nurdos.spring_security.dto.ApiResponse;
import kz.nurdos.spring_security.dto.authentication.LoginRequest;
import kz.nurdos.spring_security.dto.authentication.LoginResponse;
import kz.nurdos.spring_security.dto.authentication.TokenRefreshResponse;
import kz.nurdos.spring_security.dto.authentication.UserRegistrationRequest;
import kz.nurdos.spring_security.exception.UnsuccessfulLoginException;
import kz.nurdos.spring_security.exception.UnsuccessfulRegistrationException;
import kz.nurdos.spring_security.models.ApplicationUser;
import kz.nurdos.spring_security.models.RefreshToken;
import kz.nurdos.spring_security.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {
    private final UserRepository userRepository;
    private final EntityMapper entityMapper;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    @Autowired
    public AuthenticationService(UserRepository userRepository,
                                 EntityMapper entityMapper,
                                 AuthenticationManager authenticationManager,
                                 JwtService jwtService,
                                 RefreshTokenService refreshTokenService) {
        this.userRepository = userRepository;
        this.entityMapper = entityMapper;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
    }

    public LoginResponse loginUser(LoginRequest request) {
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    request.getUsername(), request.getPassword())
            ); //todo: what if username changes? username is the key we use to identify authentication entity, so changing it should be handled carefully
        } catch (AuthenticationException exception) {
            //todo: Consider logging the exception:
            // logger.warn("Login failed for user {}: {}", request.username(), exception.getMessage());
            throw new UnsuccessfulLoginException("Invalid login credentials");
        }
        ApplicationUser user = (ApplicationUser) authentication.getPrincipal();
        String accessToken = jwtService.generateJwtToken(user);
        String refreshToken = refreshTokenService.createRefreshToken(user).getToken();

        return new LoginResponse(true, "User logged in successfully", accessToken, refreshToken);
    }

    @Transactional
    public ApiResponse registerUser(UserRegistrationRequest request) {
        if (isUsernameTaken(request.getUsername()))
            throw new UnsuccessfulRegistrationException("Username is already taken");

        if (isEmailTaken(request.getEmail()))
            throw new UnsuccessfulRegistrationException("Email is already taken");

        ApplicationUser user = entityMapper.toApplicationUser(request);
        userRepository.save(user);

        return new ApiResponse(true, "User successfully created");
    }

    public TokenRefreshResponse refreshToken(String requestRefreshToken) { //todo: why is this in AuthenticationService class?
        return refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    refreshTokenService.deleteByToken(requestRefreshToken); //will this delete refresh token from db
                    // if an error occurs and user does not get new RT.
                    // as a result user lost old rt and did not get new one.

                    String newAccessToken = jwtService.generateJwtToken(user);
                    String newRefreshToken = refreshTokenService.createRefreshToken(user).getToken();
                    return new TokenRefreshResponse(true,"new Access and Refresh tokens generated", newAccessToken, newRefreshToken);
                })
                .orElseThrow(() -> new UnsuccessfulRefreshTokenException("Refresh token not found or invalid."));
    }

    public ApiResponse logoutUser(String refreshTokenValue) {
        refreshTokenService.deleteByToken(refreshTokenValue);
        return new ApiResponse(true, "User logged out successfully");
    }

    private boolean isUsernameTaken(String username) {
        return userRepository.existsByUsername(username);
    }
    private boolean isEmailTaken(String email) {
        return userRepository.existsByEmail(email);
    }
}
