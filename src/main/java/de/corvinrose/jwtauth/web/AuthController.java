package de.corvinrose.jwtauth.web;

import de.corvinrose.jwtauth.app.service.JwtService;
import de.corvinrose.jwtauth.domain.service.UserService;
import de.corvinrose.jwtauth.dto.UserDto;
import de.corvinrose.jwtauth.web.dto.JwtResponse;
import de.corvinrose.jwtauth.web.dto.LoginRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RequiredArgsConstructor
@RestController
@RequestMapping("/v1/auth")
public class AuthController {

  private final UserService userService;
  private final AuthenticationManager authenticationManager;
  private final JwtService jwtService;

  @PostMapping("/login")
  public ResponseEntity<Object> login(@RequestBody LoginRequest loginRequest) {
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(
            loginRequest.getEmail(), loginRequest.getPassword()));

    final Optional<UserDto> userOpt = userService.findByUsername(loginRequest.getEmail());

    if (userOpt.isEmpty()) {
      return ResponseEntity.badRequest().body("Invalid credentials");
    }

    final UserDto user = userOpt.get();

    final String accessToken = jwtService.generateAccessToken(user.getUsername());
    final String refreshToken = jwtService.generateRefreshToken(user.getUsername());

    final JwtResponse jwt =
        JwtResponse.builder().accessToken(accessToken).refreshToken(refreshToken).build();
    return ResponseEntity.ok(jwt);
  }

  @PostMapping("/refresh")
  public ResponseEntity<Object> refresh(@RequestBody String refreshToken) {

    final String email = jwtService.extractUsername(refreshToken);

    if (userService.findByUsername(email).isEmpty()) {
      return ResponseEntity.badRequest().body("Invalid credentials");
    }

    final String accessToken = jwtService.generateAccessToken(email);
    final String newRefreshToken = jwtService.generateRefreshToken(email);

    final JwtResponse jwt =
        JwtResponse.builder().accessToken(accessToken).refreshToken(newRefreshToken).build();
    return ResponseEntity.ok(jwt);
  }
}
