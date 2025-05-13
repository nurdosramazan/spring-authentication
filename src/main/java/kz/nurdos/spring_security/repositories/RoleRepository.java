package kz.nurdos.spring_security.repositories;

import kz.nurdos.spring_security.models.Role;
import kz.nurdos.spring_security.models.enums.RoleType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(RoleType roleName);
}
