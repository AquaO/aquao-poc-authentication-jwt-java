package fr.aquao.poc.authJwt.services;

import org.springframework.http.HttpHeaders;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

@Service
public class PocJwtAquoServices {

  @Value("${jwt_issuer}")
  private String jwtIssuer;

  @Value("${jwt_subject}")
  private String jwtSubject;

  @Value("${jwt_key}")
  private String jwtKey;

  public String generateJwt() {
      byte[] decodedKey = Base64.getDecoder().decode(jwtKey);
      Key key = new javax.crypto.spec.SecretKeySpec(decodedKey, "HmacSHA256");

      long nowMillis = System.currentTimeMillis();
      long expirationTime = nowMillis + 1000 * 60 * 30;

      return Jwts.builder()
              .setHeaderParam("alg", "HS256")
              .setHeaderParam("typ", "JWT")
              .setIssuedAt(new Date(nowMillis))
              .setExpiration(new Date(expirationTime))
              .setIssuer(jwtIssuer)
              .setSubject(jwtSubject)
              .signWith(key)
              .compact();
  }

  public String findSessionId(HttpHeaders httpHeaders) {
    String setCookieHeader = httpHeaders.getFirst("Set-Cookie");
    if (setCookieHeader != null) {
      Pattern pattern = Pattern.compile("SESSION=(\\w+)");
      Matcher matcher = pattern.matcher(setCookieHeader);

      if (matcher.find()) {
        System.out.println("!! New session ID found " + matcher.group(1));
        return matcher.group(1);
      }
    }
    return null;
  }
}