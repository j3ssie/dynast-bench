package com.bench.springboot;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import java.util.Optional;

@Component
class CurrentUser {
    private final UserRepository users;
    CurrentUser(UserRepository users) { this.users = users; }
    Optional<BenchUser> get() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || "anonymousUser".equals(String.valueOf(auth.getPrincipal()))) return Optional.empty();
        String principal = String.valueOf(auth.getPrincipal());
        try { return users.findById(Long.parseLong(principal)); } catch (NumberFormatException ignored) { return users.findByEmail(principal); }
    }
}
