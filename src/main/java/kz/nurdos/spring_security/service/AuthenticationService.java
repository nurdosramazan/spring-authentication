package kz.nurdos.spring_security.service;

import jakarta.servlet.http.HttpServletRequest;
import kz.nurdos.spring_security.dto.authentication.SessionsInfoResponse;
import kz.nurdos.spring_security.dto.authentication.TokenRefreshRequest;
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
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

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

    @Transactional
    public LoginResponse loginUser(LoginRequest loginRequest, HttpServletRequest httpServletRequest) {
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    loginRequest.getUsername(), loginRequest.getPassword())
            ); //todo: what if username changes? username is the key we use to identify authentication entity, so changing it should be handled carefully
        } catch (AuthenticationException exception) {
            //todo: Consider logging the exception:
            // logger.warn("Login failed for user {}: {}", loginRequest.username(), exception.getMessage());
            throw new UnsuccessfulLoginException("Invalid login credentials");
        }
        ApplicationUser user = (ApplicationUser) authentication.getPrincipal();
        String accessToken = jwtService.generateJwtToken(user);

        String clientIpAddress = getClientIpAddress(httpServletRequest);
        String userAgent = httpServletRequest.getHeader("User-Agent");
        String refreshToken = refreshTokenService.createRefreshToken(user, clientIpAddress, userAgent).getToken();

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

    @Transactional
    public TokenRefreshResponse refreshToken(TokenRefreshRequest tokenRefreshRequest, HttpServletRequest httpServletRequest) {
        String requestRefreshToken = tokenRefreshRequest.getRefreshToken();

        return refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshTokenService::verifyExpiration)
                .map(RefreshToken::getUser)
                .map(user -> {
                    refreshTokenService.deleteByToken(requestRefreshToken);

                    String newAccessToken = jwtService.generateJwtToken(user);

                    String clientIpAddress = getClientIpAddress(httpServletRequest);
                    String userAgent = httpServletRequest.getHeader("User-Agent");
                    String newRefreshToken = refreshTokenService.createRefreshToken(user, clientIpAddress, userAgent).getToken();

                    return new TokenRefreshResponse(true,"New access and refresh tokens generated", newAccessToken, newRefreshToken);
                })
                .orElseThrow(() -> new UnsuccessfulRefreshTokenException("Refresh token not found or invalid."));
    }

    @Transactional(readOnly = true)
    public SessionsInfoResponse getActiveSessions(Authentication authentication, String header) {
        Long userId = ((ApplicationUser) authentication.getPrincipal()).getId();
        List<SessionsInfoResponse.Info> sessionsInfo =
                refreshTokenService.getActiveSessionsForUser(userId);

        return new SessionsInfoResponse(true, "Sessions list successfully fetched", sessionsInfo);
    }

    @Transactional
    public ApiResponse revokeRefreshToken(TokenRefreshRequest tokenRefreshRequest, Authentication authentication) {
        String token = tokenRefreshRequest.getRefreshToken();
        Long userId = ((ApplicationUser) authentication.getPrincipal()).getId();

        refreshTokenService.revokeRefreshToken(token, userId);

        return new ApiResponse(true, "Session revoked successfully.");
    }

    @Transactional
    public ApiResponse revokeOtherSessions(TokenRefreshRequest tokenRefreshRequest, Authentication authentication) {
        String token = tokenRefreshRequest.getRefreshToken();
        Long userId = ((ApplicationUser) authentication.getPrincipal()).getId();

        refreshTokenService.revokeAllOtherRefreshTokens(token, userId);

        return new ApiResponse(true, "All other sessions revoked.");
    }

    public ApiResponse logoutUser(String refreshTokenValue) { //todo: CRITICAL: after logout(deleting refresh token from db) user can still access api's with access token
        refreshTokenService.deleteByToken(refreshTokenValue);
        return new ApiResponse(true, "User logged out successfully");
    }

    private boolean isUsernameTaken(String username) {
        return userRepository.existsByUsername(username);
    }
    private boolean isEmailTaken(String email) {
        return userRepository.existsByEmail(email);
    }

    private String getClientIpAddress(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");

        if (xfHeader == null || xfHeader.isEmpty() || "unknown".equalsIgnoreCase(xfHeader))
            return request.getRemoteAddr();

        return xfHeader.split(",")[0];
    }
}
