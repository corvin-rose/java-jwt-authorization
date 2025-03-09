package de.corvinrose.jwtauth.domain.service;

import de.corvinrose.jwtauth.dto.UserDto;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserServiceImpl implements UserService {

  private static final String TEST_USER_EMAIL = "test@test.de";
  private static final String TEST_USER_PASSWORD = "$2a$12$1jN5BxdC0ih5E7hpxZyRkOCY8PVrpqoTNTXfCThjLYEC6nhvFb2Dy"; // PW: 1234

  @Override
  public Optional<UserDto> findByUsername(String username) {
    return Optional.of(
        UserDto.builder().username(TEST_USER_EMAIL).password(TEST_USER_PASSWORD).build());
  }
}
