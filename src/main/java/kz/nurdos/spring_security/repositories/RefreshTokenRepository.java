package kz.nurdos.spring_security.repositories;

import kz.nurdos.spring_security.models.ApplicationUser;
import kz.nurdos.spring_security.models.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);

    @Modifying
    int deleteByUser(ApplicationUser applicationUser);

    Optional<RefreshToken> findByUserId(Long userId); //Point C: Find a use to this method as this has no usages

    List<RefreshToken> findAllByUserIdAndExpiryDateAfter(Long userId, Instant currentTime);
}
