package kz.nurdos.spring_security.service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;

@Service
public class JwtService {
    private final long expirationMilliSeconds = 14 * 24 * 60 * 60 * 1000;

    @Value("${jwt_secret_key}")
    private String jwt_secret_key;
    public String generateJwtToken(String username) {
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + expirationMilliSeconds))
                .signWith(getSignInKey())
                .compact();
    }

    private Key getSignInKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwt_secret_key));
    }
}
