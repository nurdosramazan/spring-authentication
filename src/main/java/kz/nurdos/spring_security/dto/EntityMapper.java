package kz.nurdos.spring_security.dto;

import kz.nurdos.spring_security.dto.authentication.UserRegistrationRequest;
import kz.nurdos.spring_security.models.ApplicationUser;
import kz.nurdos.spring_security.models.Role;
import kz.nurdos.spring_security.models.enums.RoleType;
import kz.nurdos.spring_security.repositories.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
public class EntityMapper {
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;

    @Autowired
    public EntityMapper(PasswordEncoder passwordEncoder, RoleRepository roleRepository) {
        this.passwordEncoder = passwordEncoder;
        this.roleRepository = roleRepository;
    }

    public ApplicationUser toApplicationUser(UserRegistrationRequest request) {
        Role role = roleRepository.findByRoleName(RoleType.ROLE_USER).orElseThrow();

        ApplicationUser user = new ApplicationUser();
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setEmail(request.getEmail());
        user.setRoles(Set.of(role));

        return user;
    }
}
