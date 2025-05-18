package kz.nurdos.spring_security.service;

import kz.nurdos.spring_security.dto.authentication.SessionsInfoResponse;
import kz.nurdos.spring_security.exception.UnsuccessfulRefreshTokenException;
import org.springframework.transaction.annotation.Transactional;
import kz.nurdos.spring_security.exception.RefreshTokenExpiredException;
import kz.nurdos.spring_security.models.ApplicationUser;
import kz.nurdos.spring_security.models.RefreshToken;
import kz.nurdos.spring_security.repositories.RefreshTokenRepository;
import kz.nurdos.spring_security.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;

    private final UserRepository userRepository;

    @Value("${jwt.refresh-token.expiration-ms}")
    private Long refreshTokenDurationMs;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository, UserRepository userRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    @Transactional
    public RefreshToken createRefreshToken(ApplicationUser user, String ipAddress, String userAgent) {
        // keep history, e.g. every RefreshToken kept in the history, or maybe archive or log, later implementation
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setIpAddress(ipAddress);
        refreshToken.setUserAgent(userAgent);
        refreshToken.setLastUsedAt(Instant.now());

        return refreshTokenRepository.save(refreshToken);
    }

    @Transactional
    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new RefreshTokenExpiredException("Refresh token " + token.getToken() +
                    " was expired. Please make a new sign in request");
        }

        return token;
    }

    public List<SessionsInfoResponse.Info> getActiveSessionsForUser(Long userId) {
        return refreshTokenRepository.findAllByUserIdAndExpiryDateAfter(userId, Instant.now())
                .stream()
                .map(refreshToken -> new SessionsInfoResponse.Info(
                            refreshToken.getToken(), //hm? token? token or id so? Point B: affected here too
                            refreshToken.getDeviceName(),
                            refreshToken.getIpAddress(),
                            refreshToken.getUserAgent(),
                            refreshToken.getCreatedAt(),
                            refreshToken.getLastUsedAt(),
                            refreshToken.getExpiryDate(),
                            false //why always false?
                ))
                .toList();
    }

    @Transactional
    public void revokeRefreshToken(String currentUserToken, Long userId) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(currentUserToken)
                .orElseThrow(() -> new UnsuccessfulRefreshTokenException("Refresh token not found or invalid."));

        Long tokenUserId = refreshToken.getUser().getId();
        if (!userId.equals(tokenUserId)) {
            // Log this attempt: User X tried to revoke token of user Y
            throw new SecurityException("User not authorized to revoke this refresh token.");
        }
        refreshTokenRepository.delete(refreshToken);
    }

    @Transactional
    public void revokeAllOtherRefreshTokens(String currentUserToken, Long userId) {
        //maybe delete in batch? will this keep open-closing pool and therefore pressure on db
        //or maybe not, usually people will log in to at most 3-4 devices, so should not be a problem
        //however, attackers might try to break, maybe limit number of logged id=n devices.
        List<RefreshToken> refreshTokens =
                refreshTokenRepository.findAllByUserIdAndExpiryDateAfter(userId, Instant.now());
        for (RefreshToken refreshToken : refreshTokens) {
            if (!refreshToken.getToken().equals(currentUserToken))
                refreshTokenRepository.delete(refreshToken);
        }
    }

    @Transactional
    public int deleteByUserId(Long userId) { //is this method useless at this point?
        // Since we are using  findAllByUserIdAndExpiryDateAfter(Long userId, Instant currentTime).
        // are these two ways to do the same thing?
        //Point D: if not, find a way to make user of this method.
        ApplicationUser user = userRepository.findById(userId).orElseThrow();
        return refreshTokenRepository.deleteByUser(user);
    }

    @Transactional
    public void deleteByToken(String token) {
        refreshTokenRepository.findByToken(token).ifPresent(refreshTokenRepository::delete);
    }

    @Transactional
    public void save(RefreshToken refreshToken) { //Is this needed now? Well, for updating session infos when logging in other times
        //therfore Point E: make us of this method too, probably involves updating session device info, log in info etc.
        refreshTokenRepository.save(refreshToken);
    }
}
