package com.filipovski.drboson.sharedkernel.security;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;

@Component
public class JwtTokenAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenHandler tokenHandler;

    public JwtTokenAuthenticationFilter(JwtTokenHandler tokenHandler) {
        this.tokenHandler = tokenHandler;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        try {
            String token = tokenHandler.resolveToken(request);
            Claims claims = tokenHandler.validateToken(token);

            String username = tokenHandler.claimUsername(claims);
            String userId = tokenHandler.claimUserId(claims);

            if(!Strings.isNullOrEmpty(username) && !Strings.isNullOrEmpty(userId)) {
                AuthenticatedUser user = AuthenticatedUser.from(username, userId);

                UsernamePasswordAuthenticationToken auth =
                        new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>());

                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        } catch (Exception e) {
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }
}
