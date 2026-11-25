package com.invex.test.authentication.security.user;

import com.invex.test.authentication.domain.model.Role;
import com.invex.test.authentication.domain.model.AuthenticationUser;
import com.invex.test.authentication.repository.AuthenticationUserRepository;
import com.invex.test.authentication.security.AuthorizationCodes;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.LinkedHashSet;
import java.util.Set;

@Service
public class DatabaseUserDetailsService implements UserDetailsService {

    private final AuthenticationUserRepository userRepository;

    public DatabaseUserDetailsService(AuthenticationUserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        AuthenticationUser user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User was not found"));
        return org.springframework.security.core.userdetails.User.withUsername(user.getUsername())
                .password(user.getPasswordHash())
                .authorities(authoritiesOf(user))
                .disabled(!user.isEnabled())
                .build();
    }

    private static Set<GrantedAuthority> authoritiesOf(AuthenticationUser user) {
        Set<GrantedAuthority> authorities = new LinkedHashSet<>();
        for (Role role : user.getRoles()) {
            authorities.add(new SimpleGrantedAuthority(AuthorizationCodes.ROLE_PREFIX + role.getCode()));
        }
        return authorities;
    }
}
