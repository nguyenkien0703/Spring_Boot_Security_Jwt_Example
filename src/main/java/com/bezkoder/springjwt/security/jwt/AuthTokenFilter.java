package com.bezkoder.springjwt.security.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.bezkoder.springjwt.security.services.UserDetailsServiceImpl;

public class AuthTokenFilter extends OncePerRequestFilter {
  @Autowired
  private JwtUtils jwtUtils;

  @Autowired
  private UserDetailsServiceImpl userDetailsService;

  private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

  /*
   * What we do inside doFilterInternal():
   * – get JWT from the Authorization header (by removing Bearer prefix)
   * – if the request has JWT, validate it, parse username from it
   * – from username, get UserDetails to create an Authentication object
   * – set the current UserDetails in SecurityContext using
   * setAuthentication(authentication) method.
   * 
   * After this, everytime you want to get UserDetails, just use SecurityContext
   * like this:
   * 
   * UserDetails userDetails =
   * (UserDetails)
   * SecurityContextHolder.getContext().getAuthentication().getPrincipal();
   * 
   * // userDetails.getUsername()
   * // userDetails.getPassword()
   * // userDetails.getAuthorities()
   */

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    try {
      String jwt = parseJwt(request);
      if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
        String username = jwtUtils.getUserNameFromJwtToken(jwt);

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        UsernamePasswordAuthenticationToken authentication =
            new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities());
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        SecurityContextHolder.getContext().setAuthentication(authentication);
      }
    } catch (Exception e) {
      logger.error("Cannot set user authentication: {}", e);
    }

    filterChain.doFilter(request, response);
  }

  private String parseJwt(HttpServletRequest request) {
    /*
     * phân tihcsh JWT từ đối tượng HttpServletRequest dc gửi lên do ng dùng dửi
     * request,
     * nó sẽ truy xuất giá trị của Authorization từ HttpServletRequest bằng cáhc gọi request.getHeader("Authorization");
     * nó sẽ kiểm tra nếu giá trị tồn tại và bắt đầu bằng"Bearer" thì nó trả về 1 chuỗi mới dc cắt
     * từ chuỗi ban đàu từ kí tự 7 đến kí tự cuối cùng , còn nếu k tồn tại giá trị thì trả về null
     * 
     */
    String headerAuth = request.getHeader("Authorization");

    if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
      return headerAuth.substring(7, headerAuth.length());
    }

    return null;
  }
}
