package kz.nurdos.spring_security.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;


import javax.crypto.SecretKey;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class JwtService {
    @Value("${jwt.secret-key}")
    private String jwtSecretKey;

    @Value("${jwt.access-token.expiration-ms}")
    private long accessTokenExpirationMilliSeconds;
    public static final String ROLES_CLAIM = "roles";

    private SecretKey signInKey;

    @PostConstruct
    private void init() {
        this.signInKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecretKey));
    }
    public String generateJwtToken(UserDetails userDetails) {
        String username = userDetails.getUsername();
        List<String> roles = userDetails.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        Map<String, Object> claims = new HashMap<>();
        claims.put(ROLES_CLAIM, roles);

        return Jwts.builder()
                .claims(claims)
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + accessTokenExpirationMilliSeconds))
                .signWith(signInKey)
                .compact();
    }
    public String extractUsername(String token) {
        Claims claims = extractClaims(token);
        return claims.getSubject();
    }

    public List<String> extractRoles(String token) {
        Claims claims = extractClaims(token);
        Object rolesClaim = claims.get(ROLES_CLAIM);

        if (rolesClaim instanceof List<?> roles) {
            return roles.stream()
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .toList();
        }
        return Collections.emptyList();
    }

    private Claims extractClaims(String token) {
        return Jwts.parser()
                .verifyWith(signInKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
