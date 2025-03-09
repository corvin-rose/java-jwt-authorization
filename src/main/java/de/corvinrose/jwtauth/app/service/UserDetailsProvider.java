package de.corvinrose.jwtauth.app.service;

import de.corvinrose.jwtauth.domain.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

@RequiredArgsConstructor
@Service
public class UserDetailsProvider implements UserDetailsService {

  private final UserService userService;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    return userService
        .findByUsername(username)
        .map(
            user -> {
              return new User(
                  user.getUsername(),
                  user.getPassword(),
                  Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));
            })
        .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
  }
}
