package de.corvinrose.jwtauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

@SpringBootApplication
public class JwtauthApplication {

  public static void main(String[] args) {
    SpringApplication.run(JwtauthApplication.class, args);

    System.out.println("Generated Token:");
    System.out.println(generateSecret());
  }

  public static String generateSecret() {
    try {
      KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA512");
      SecretKey secretKey = keyGenerator.generateKey();
      return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    } catch (NoSuchAlgorithmException e) {
      return null;
    }
  }
}
