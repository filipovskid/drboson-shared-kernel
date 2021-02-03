package com.filipovski.drboson.sharedkernel.security;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import javax.naming.AuthenticationException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

@Component
public class JwtTokenHandler {

    private final JwtConfig jwtConfig;

    public JwtTokenHandler(JwtConfig jwtConfig) {
        this.jwtConfig = jwtConfig;
    }

    public String resolveToken(HttpServletRequest request) throws AuthenticationException {
//        String header = request.getHeader(jwtConfig.getHeader());
//
//        if(header == null || !header.startsWith(jwtConfig.getPrefix()))
//            throw new AuthenticationException();
//
//        String token = header.replace(jwtConfig.getPrefix(), "").trim();

        Cookie tokenCookie = WebUtils.getCookie(request, jwtConfig.getCookieName());

        if (tokenCookie == null || Strings.isNullOrEmpty(tokenCookie.getValue()))
            throw new AuthenticationException();

        return tokenCookie.getValue();
    }

    public String resolveToken(ServerHttpRequest request) {
        String header = request.getHeaders().getFirst(jwtConfig.getHeader());

        if(header == null || !header.startsWith(jwtConfig.getPrefix()))
            return null;

        String token = header.replace(jwtConfig.getPrefix(), "").trim();

        return token;
    }

    public Claims validateToken(String token) {
        return Jwts.parser()
                .setSigningKey(jwtConfig.getSecret())
                .parseClaimsJws(token)
                .getBody();
    }

    public String claimUsername(Claims claims) {
        return claims.getSubject();
    }

    public String claimUserId(Claims claims) {
        return claims.get("user_id", String.class);
    }
}
