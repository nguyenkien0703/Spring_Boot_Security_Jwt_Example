package com.bezkoder.springjwt.security.jwt;

import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.bezkoder.springjwt.security.services.UserDetailsImpl;
import io.jsonwebtoken.*;

/**
 * This class has 3 funtions:
 * 
 * generate a JWT from username, date, expiration, secret
 * get username from JWT
 * validate a JWT
 */

@Component
public class JwtUtils {
  private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);



  @Value("${bezkoder.app.jwtSecret}")
  private String jwtSecret;

  @Value("${bezkoder.app.jwtExpirationMs}")
  private int jwtExpirationMs;

  public String generateJwtToken(Authentication authentication) {

    UserDetailsImpl userPrincipal = (UserDetailsImpl) authentication.getPrincipal();

    return Jwts.builder()
        .setSubject((userPrincipal.getUsername()))
        .setIssuedAt(new Date())
        .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
        .signWith(SignatureAlgorithm.HS512, jwtSecret)
        .compact();// trả về dưới dạng chuỗi 
        
  }



  public String getUserNameFromJwtToken(String token) {
    /**
     * Jwts.parser(): phan tích cú pháp token
     * setSigningKey(jwtSecret)L hiểu nôm na nó như là cái
     * signature(hear+payload(hai cais naỳ là thuộc cấu
     * trúc của JWT), secret) kiểu như là encode để thông tin dc bảo maật hơn
     * 
     * Việc phân tích cú pháp thực tế của JWT được thực hiện bằng cách gọi phương
     * thức parseClaimsJws(token). Điều này trả về một đối tượng Jws, đại diện cho
     * JWT ở dạng được phân tích cú pháp.
     * --> như v là sau khi gọi parseClaimsJws với tham số truyênf vào là 1 token thì nó return về 1 đói tượng JWT
     * getBody() trả về payload trong cấu trúc của JWT
     * gétubject trả về người dùng đã đc authenticate
     * nói tóm lại, chuỗi này lấy ra tên ng dùng từ 1 JWT sử dụng thư viện JWT, đầu vào là 1 token hợp lệ 
     * và đầu ra là 1 chuỗi, chính là tên của nguiời dunggf
     * 
     */
    return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
  }

  public boolean validateJwtToken(String authToken) {
    try {
      Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
      return true;
    } catch (SignatureException e) {
      logger.error("Invalid JWT signature: {}", e.getMessage());
    } catch (MalformedJwtException e) {
      logger.error("Invalid JWT token: {}", e.getMessage());
    } catch (ExpiredJwtException e) {
      logger.error("JWT token is expired: {}", e.getMessage());
    } catch (UnsupportedJwtException e) {
      logger.error("JWT token is unsupported: {}", e.getMessage());
    } catch (IllegalArgumentException e) {
      logger.error("JWT claims string is empty: {}", e.getMessage());
    }

    return false;
  }
}
