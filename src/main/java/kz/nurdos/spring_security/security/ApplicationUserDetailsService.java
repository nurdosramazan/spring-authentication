package kz.nurdos.spring_security.security;

import jakarta.transaction.Transactional;
import kz.nurdos.spring_security.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class ApplicationUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;
    @Autowired
    public ApplicationUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
    @Override
    @Transactional //todo: is this even needed here? readOnly = true?
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("no account found for " + username));
        // If you want to ensure roles are loaded within this transaction (though Spring Security usually does this by calling getAuthorities()):
        // Hibernate.initialize(user.getRoles()); // Or user.getAuthorities().size(); to trigger it
    }
}
