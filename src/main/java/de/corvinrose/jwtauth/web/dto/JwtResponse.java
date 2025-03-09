package de.corvinrose.jwtauth.web.dto;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class JwtResponse {
  private String accessToken;
  private String refreshToken;
}
