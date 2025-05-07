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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {
    private final UserRepository userRepository;
    private final EntityMapper entityMapper;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    @Autowired
    public AuthenticationService(UserRepository userRepository,
                                 EntityMapper entityMapper,
                                 AuthenticationManager authenticationManager,
                                 JwtService jwtService) {
        this.userRepository = userRepository;
        this.entityMapper = entityMapper;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
    }

    public String login(LoginRequest request) {
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    request.username(), request.password())
            );
        } catch (AuthenticationException exception) {
            throw new UnsuccessfulLoginException("Invalid login credentials");
        }

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        return jwtService.generateJwtToken(userDetails);
    }

    @Transactional
    public void registerUser(UserRegistrationRequest request) {
        if (isUsernameTaken(request.getUsername()))
            throw new UnsuccessfulRegistrationException("Username is already taken");

        if (isEmailTaken(request.getEmail()))
            throw new UnsuccessfulRegistrationException("Email is already taken");

        ApplicationUser user = entityMapper.toApplicationUser(request);
        userRepository.save(user);
    }

    private boolean isUsernameTaken(String username) {
        return userRepository.existsByUsername(username);
    }
    private boolean isEmailTaken(String email) {
        return userRepository.existsByEmail(email);
    }
}
