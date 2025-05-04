package kz.nurdos.spring_security.service;

import jakarta.transaction.Transactional;
import kz.nurdos.spring_security.dto.authentication.LoginRequest;
import kz.nurdos.spring_security.dto.authentication.UserRegistrationRequest;
import kz.nurdos.spring_security.exception.UnsuccessfulRegistrationException;
import kz.nurdos.spring_security.models.ApplicationUser;
import kz.nurdos.spring_security.repositories.UserRepository;
import kz.nurdos.spring_security.security.ApplicationUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {
    private final UserRepository userRepository;
    private final EntityMapperService entityMapperService;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    @Autowired
    public AuthenticationService(UserRepository userRepository,
                                 EntityMapperService entityMapperService,
                                 AuthenticationManager authenticationManager,
                                 JwtService jwtService) {
        this.userRepository = userRepository;
        this.entityMapperService = entityMapperService;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
    }

    public String login(LoginRequest request) {
        return jwtService.generateJwtToken(request.username());
    }

    @Transactional
    public void registerUser(UserRegistrationRequest request) {
        if (isUsernameTaken(request.username()))
            throw new UnsuccessfulRegistrationException("Username is already taken");

        ApplicationUser user = entityMapperService.toApplicationUser(request);
        userRepository.save(user);
    }

    private boolean isUsernameTaken(String username) {
        return userRepository.existsByUsername(username);
    }
}
