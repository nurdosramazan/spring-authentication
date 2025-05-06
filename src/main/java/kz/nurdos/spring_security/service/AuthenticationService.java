package kz.nurdos.spring_security.service;

import jakarta.transaction.Transactional;
import kz.nurdos.spring_security.dto.authentication.LoginRequest;
import kz.nurdos.spring_security.dto.authentication.UserRegistrationRequest;
import kz.nurdos.spring_security.exception.UnsuccessfulLoginException;
import kz.nurdos.spring_security.exception.UnsuccessfulRegistrationException;
import kz.nurdos.spring_security.models.ApplicationUser;
import kz.nurdos.spring_security.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {
    private final UserRepository userRepository;
    private final EntityMapper entityMapper;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Autowired
    public AuthenticationService(UserRepository userRepository,
                                 EntityMapper entityMapper,
                                 AuthenticationManager authenticationManager,
                                 JwtService jwtService,
                                 UserDetailsService userDetailsService) {
        this.userRepository = userRepository;
        this.entityMapper = entityMapper;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    public String login(LoginRequest request) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    request.username(), request.password())
            );
        } catch (AuthenticationException exception) {
            throw new UnsuccessfulLoginException("Invalid login credentials");
        }

        UserDetails userDetails = userDetailsService.loadUserByUsername(request.username());
        return jwtService.generateJwtToken(userDetails.getUsername());
    }

    @Transactional
    public void registerUser(UserRegistrationRequest request) {
        if (isUsernameTaken(request.username()))
            throw new UnsuccessfulRegistrationException("Username is already taken");

        ApplicationUser user = entityMapper.toApplicationUser(request);
        userRepository.save(user);
    }

    private boolean isUsernameTaken(String username) {
        return userRepository.existsByUsername(username);
    }
}
