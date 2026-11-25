package com.invex.test.authentication.security.token;

import com.invex.test.authentication.security.AuthorizationCodes;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

@Component
public class AccessTokenGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private final JwtGrantedAuthoritiesConverter scopeAuthorities;

    public AccessTokenGrantedAuthoritiesConverter() {
        this.scopeAuthorities = new JwtGrantedAuthoritiesConverter();
        this.scopeAuthorities.setAuthorityPrefix(AuthorizationCodes.SCOPE_PREFIX);
    }

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Set<GrantedAuthority> authorities = new LinkedHashSet<>();
        Collection<GrantedAuthority> scopes = scopeAuthorities.convert(jwt);
        if (scopes != null) {
            authorities.addAll(scopes);
        }
        addClaim(jwt, IdentityTokenCustomizer.ROLES, AuthorizationCodes.ROLE_PREFIX, authorities);
        return authorities;
    }

    private static void addClaim(Jwt jwt, String claimName, String prefix, Set<GrantedAuthority> authorities) {
        Object claim = jwt.getClaims().get(claimName);
        if (!(claim instanceof List<?> values)) {
            return;
        }
        for (Object value : values) {
            if (value instanceof String authority && !authority.isBlank()) {
                authorities.add(new SimpleGrantedAuthority(prefix + authority));
            }
        }
    }
}
