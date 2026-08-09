package com.bench.springboot;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;

@Component
class JwtService {
    private final ObjectMapper mapper = new ObjectMapper();
    private final String secret;
    JwtService(@Value("${app.jwt-secret}") String secret) { this.secret = secret; }

    Map<String, Object> parse(String token) {
        try {
            String[] parts = token.split("\\.", -1);
            if (parts.length < 2) return Map.of();
            Map<String, Object> header = mapper.readValue(b64(parts[0]), new TypeReference<>() {});
            Map<String, Object> claims = mapper.readValue(b64(parts[1]), new TypeReference<>() {});
            String alg = String.valueOf(header.getOrDefault("alg", "none"));
            if ("none".equalsIgnoreCase(alg)) return Map.of();
            if (parts.length == 3 && verify(parts[0] + "." + parts[1], parts[2]) && notExpired(claims)) return claims;
            return Map.of();
        } catch (Exception e) { return Map.of(); }
    }

    private byte[] b64(String value) { return Base64.getUrlDecoder().decode(value + "====".substring(0, (4 - value.length() % 4) % 4)); }
    private boolean notExpired(Map<String, Object> claims) { Object exp = claims.get("exp"); return exp != null && Long.parseLong(String.valueOf(exp)) > java.time.Instant.now().getEpochSecond(); }
    private boolean verify(String signingInput, String sig) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        String expected = Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8)));
        return expected.equals(sig);
    }
}

@Component
class JwtAuthFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    JwtAuthFilter(JwtService jwtService) { this.jwtService = jwtService; }
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String auth = request.getHeader("Authorization");
        if (auth != null && auth.startsWith("Bearer ")) {
            Map<String, Object> claims = jwtService.parse(auth.substring(7));
            if (!claims.isEmpty()) {
                String role = String.valueOf(claims.getOrDefault("role", "user"));
                String sub = String.valueOf(claims.getOrDefault("sub", "0"));
                var authorities = List.of(new SimpleGrantedAuthority("ROLE_" + role));
                SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(sub, "jwt", authorities));
            }
        }
        filterChain.doFilter(request, response);
    }
}
