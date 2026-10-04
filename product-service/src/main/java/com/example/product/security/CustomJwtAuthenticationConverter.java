package com.example.product.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

@Component
public class CustomJwtAuthenticationConverter {

    public AbstractAuthenticationToken convert(Map<String, Object> claims) {
        String username = (String) claims.get("sub");
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();

        // 1. Lấy List<String> từ claim "permissions"
        Object permissionsObj = claims.get("permissions");
        if (permissionsObj instanceof Collection<?> permissions) {
            // 2. Map từng String thành SimpleGrantedAuthority
            for (Object perm : permissions) {
                if (perm != null) {
                    authorities.add(new SimpleGrantedAuthority(perm.toString()));
                }
            }
        }

        // Map cả roles nếu có
        Object rolesObj = claims.get("roles");
        if (rolesObj instanceof Collection<?> roles) {
            for (Object role : roles) {
                if (role != null) {
                    String roleStr = role.toString();
                    authorities.add(new SimpleGrantedAuthority(roleStr));
                    if (!roleStr.startsWith("ROLE_")) {
                        authorities.add(new SimpleGrantedAuthority("ROLE_" + roleStr));
                    }
                }
            }
        }

        // 3. Trả về UsernamePasswordAuthenticationToken chứa danh sách Authorities này
        return new UsernamePasswordAuthenticationToken(username, null, authorities);
    }
}
