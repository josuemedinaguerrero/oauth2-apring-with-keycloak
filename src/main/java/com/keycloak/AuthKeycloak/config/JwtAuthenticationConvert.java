package com.keycloak.AuthKeycloak.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

@Component
public class JwtAuthenticationConvert implements Converter<Jwt, AbstractAuthenticationToken> {

  private JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

  @Value("${jwt.auth.converter.principle-attribute}")
  private String principalAttribute;

  @Value("${jwt.auth.converter.resource-id}")
  private String resourceId;

  @Override
  public AbstractAuthenticationToken convert(Jwt jwt) {
    Collection<GrantedAuthority> authorities = Stream
        .concat(jwtGrantedAuthoritiesConverter.convert(jwt).stream(), extractResourceRoles(jwt).stream())
        .toList();

    return new JwtAuthenticationToken(jwt, authorities, getPrincipleName(jwt));
  }

  private String getPrincipleName(Jwt jwt) {
    String clainName = JwtClaimNames.SUB;

    if (principalAttribute != null) {
      clainName = principalAttribute;
    }

    return jwt.getClaim(clainName);
  }

  private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt jwt) {
    Map<String, Object> resourceAccess;
    Map<String, Object> resource;
    Collection<String> resourceRoles;

    if (jwt.getClaim("resource_access") == null) {
      return List.of();
    }

    resourceAccess = jwt.getClaim("resource_access");

    if (resourceAccess.get(resourceId) == null) {
      return List.of();
    }

    resource = (Map<String, Object>) resourceAccess.get(resourceId);

    if (resource.get("roles") == null) {
      return List.of();
    }

    resourceRoles = (Collection<String>) resource.get("roles");

    return resourceRoles.stream()
        .map(role -> new SimpleGrantedAuthority("ROLE_".concat(role)))
        .toList();
  }

}
