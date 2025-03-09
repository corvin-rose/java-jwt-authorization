package de.corvinrose.jwtauth.app.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
  @Value("${spring.security.jwt-secret}")
  private String jwtSecret;

  private static final long ACCESS_TOKEN_EXPIRATION_TIME = 1000L * 20 * 5; // 5 Minuten
  private static final long REFRESH_TOKEN_EXPIRATION_TIME = 1000L * 60 * 60 * 24; // 1 Tag

  public String generateAccessToken(String username) {
    return generateToken(username, ACCESS_TOKEN_EXPIRATION_TIME);
  }

  public String generateRefreshToken(String username) {
    return generateToken(username, REFRESH_TOKEN_EXPIRATION_TIME);
  }

  private String generateToken(String username, long expirationTime) {
    final Map<String, Object> claims = new HashMap<>();
    claims.put("role", "ROLE_USER");

    return Jwts.builder()
        .claims()
        .add(claims)
        .subject(username)
        .issuedAt(new Date())
        .expiration(new Date(System.currentTimeMillis() + expirationTime))
        .and()
        .signWith(getSecretKey())
        .compact();
  }

  public String extractUsername(String token) {
    return extractClaim(token, Claims::getSubject);
  }

  public boolean validateToken(String token, UserDetails userDetails) {
    final String username = extractUsername(token);
    return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
  }

  private SecretKey getSecretKey() {
    final byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
    return Keys.hmacShaKeyFor(keyBytes);
  }

  private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
    final Claims claims =
        Jwts.parser().verifyWith(getSecretKey()).build().parseSignedClaims(token).getPayload();
    return claimsResolver.apply(claims);
  }

  private boolean isTokenExpired(String token) {
    return extractClaim(token, Claims::getExpiration).before(new Date());
  }
}
