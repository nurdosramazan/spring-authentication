package kz.nurdos.spring_security.repositories;

import kz.nurdos.spring_security.models.ApplicationUser;
import kz.nurdos.spring_security.models.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    //TODO: verify all these repo methods
    Optional<RefreshToken> findByToken(String token);

    @Modifying
    int deleteByUser(ApplicationUser applicationUser);

    Optional<RefreshToken> findByUserId(Long userId);
}
