package kz.nurdos.spring_security.service;

import jakarta.transaction.Transactional;
import kz.nurdos.spring_security.exception.RefreshTokenExpiredException;
import kz.nurdos.spring_security.models.ApplicationUser;
import kz.nurdos.spring_security.models.RefreshToken;
import kz.nurdos.spring_security.repositories.RefreshTokenRepository;
import kz.nurdos.spring_security.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
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

    public Optional<RefreshToken> findByToken(String token) { //todo: consider returning RefreshToken using orElse/orElseThrow
        return refreshTokenRepository.findByToken(token);
    }

    @Transactional
    public RefreshToken createRefreshToken(ApplicationUser user) { //why not UserDetails as parameter?
        refreshTokenRepository.findByUserId(user.getId())
                .ifPresent(refreshTokenRepository::delete); //one session if user has multiple devices?

        RefreshToken refreshToken = new RefreshToken(); //maybe have an args constructor?
        refreshToken.setUser(user);
        refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
        refreshToken.setToken(UUID.randomUUID().toString());

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

    @Transactional
        public int deleteByUserId(Long userId) {
        ApplicationUser user = userRepository.findById(userId).orElseThrow();
        return refreshTokenRepository.deleteByUser(user);
    }

    @Transactional
    public void deleteByToken(String token) {
        refreshTokenRepository.findByToken(token).ifPresent(refreshTokenRepository::delete);
    }
}
