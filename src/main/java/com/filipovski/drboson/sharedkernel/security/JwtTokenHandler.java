package com.filipovski.drboson.sharedkernel.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.stereotype.Component;

import javax.naming.AuthenticationException;
import javax.servlet.http.HttpServletRequest;

@Component
public class JwtTokenHandler {

    private final JwtConfig jwtConfig;

    public JwtTokenHandler(JwtConfig jwtConfig) {
        this.jwtConfig = jwtConfig;
    }

    public String resolveToken(HttpServletRequest request) throws AuthenticationException {
        String header = request.getHeader(jwtConfig.getHeader());

        if(header == null || !header.startsWith(jwtConfig.getPrefix()))
            throw new AuthenticationException();

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
