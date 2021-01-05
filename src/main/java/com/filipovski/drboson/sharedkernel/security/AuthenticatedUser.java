package com.filipovski.drboson.sharedkernel.security;

import com.filipovski.drboson.sharedkernel.domain.base.ValueObject;
import lombok.Getter;

import java.util.Objects;

@Getter
public class AuthenticatedUser implements ValueObject {
    private String userId;
    private String username;

    private AuthenticatedUser(String username, String userId) {
        this.username = username;
        this.userId = userId;
    }

    public static AuthenticatedUser from(String username, String userId) {
        Objects.requireNonNull(username);
        Objects.requireNonNull(userId);

        return new AuthenticatedUser(username, userId);
    }
}
