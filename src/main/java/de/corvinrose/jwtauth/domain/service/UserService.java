package de.corvinrose.jwtauth.domain.service;

import de.corvinrose.jwtauth.dto.UserDto;

import java.util.Optional;

public interface UserService {
  Optional<UserDto> findByUsername(String username);
}
