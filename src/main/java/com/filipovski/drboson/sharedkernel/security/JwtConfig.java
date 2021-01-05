package com.filipovski.drboson.sharedkernel.security;

import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.stereotype.Component;

@Data
@PropertySource("classpath:security/jwt.properties")
@Configuration
public class JwtConfig {

    @Value("${jwt.header:Authorization}")
    private String header;

    @Value("${jwt.cookie.name:drbosonJWT}")
    private String cookieName;

    @Value("${jwt.prefix:Bearer }")
    private String prefix;

    @Value("#{${jwt.expiration:10000*60*60}}")
    private int expiration;

    @Value("${jwt.secret:JwtSecretKey}")
    private String secret;
}