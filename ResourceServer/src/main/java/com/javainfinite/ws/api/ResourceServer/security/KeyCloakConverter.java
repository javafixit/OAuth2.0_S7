package com.javainfinite.ws.api.ResourceServer.security;


import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class KeyCloakConverter implements Converter<Jwt, Collection<GrantedAuthority>> {


    @Override
    public Collection<GrantedAuthority> convert(Jwt source) {

        Map<String, Object> realmAccess = (Map<String, Object>) source.getClaims().get("realm_access");

        if (realmAccess == null || realmAccess.size() == 0) {
            return new ArrayList<>();
        }

        return ((List<String>) realmAccess.get("roles"))
                .stream().map(rolename -> "ROLE_" + rolename)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
}
