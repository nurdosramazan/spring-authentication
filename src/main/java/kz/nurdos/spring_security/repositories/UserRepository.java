package kz.nurdos.spring_security.repositories;

import kz.nurdos.spring_security.models.ApplicationUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<ApplicationUser, Long> {
    Optional<ApplicationUser> findByUsername(String username);
    @Query("SELECT u FROM ApplicationUser u LEFT JOIN FETCH u.roles WHERE u.username = :username")
    Optional<ApplicationUser> findByUsernameWithRoles(@Param("username") String username);
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
}
