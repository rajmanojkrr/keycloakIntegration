package com.example.demo.config;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;

public class CustomKeycloakAuthenticationProvider extends KeycloakAuthenticationProvider {

	public CustomKeycloakAuthenticationProvider(ApplicationContext appCtx) {
		this.appCtx = appCtx;
	}

	private static final Logger LOGGER = LoggerFactory.getLogger(CustomKeycloakAuthenticationProvider.class);

	private ApplicationContext appCtx;

	/**
	 * 
	 * authenticate - Customer Authentication
	 * 
	 * @param authentication
	 * @return
	 * @throws AuthenticationException
	 */
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		KeycloakAuthenticationToken token = (KeycloakAuthenticationToken) authentication;
		Collection<? extends GrantedAuthority> grantedAuthorities = addUserSpecificAuthorities(authentication, null);
		return new KeycloakAuthenticationToken(token.getAccount(), token.isInteractive(), grantedAuthorities);
	}

	/**
	 * mapAuthorityMapper - Mapping the prefix
	 * 
	 * @return
	 */
	protected SimpleAuthorityMapper mapAuthorityMapper() {
		SimpleAuthorityMapper grantedAuthorityMapper = new SimpleAuthorityMapper();
		grantedAuthorityMapper.setPrefix("ROLE_");
		grantedAuthorityMapper.setConvertToUpperCase(true);
		return grantedAuthorityMapper;
	}

	/**
	 * Adding custom Roles either from Redis addUserSpecificAuthorities
	 * 
	 * @param authentication
	 * @param authorities
	 * @return
	 */
	protected Collection<? extends GrantedAuthority> addUserSpecificAuthorities(Authentication authentication,
			Collection<? extends GrantedAuthority> authorities) {
		List<GrantedAuthority> result = new ArrayList<>();
		if (authorities != null)
			result.addAll(authorities);
		result.add(new SimpleGrantedAuthority("T_USER"));
		return result;
	}

	/**
	 * 
	 * addKeycloakRoles - Mapping the roles from the Keycloak
	 * 
	 * @param token
	 * @return
	 */
	protected Collection<? extends GrantedAuthority> addKeycloakRoles(KeycloakAuthenticationToken token) {
		Collection<GrantedAuthority> keycloakRoles = new ArrayList<>();
		for (String role : token.getAccount().getRoles()) {
			keycloakRoles.add(new SimpleGrantedAuthority(role));
		}
		return keycloakRoles;
	}

	private Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {
		return authorities;
	}

	@Override
	public boolean supports(Class<?> aClass) {
		return KeycloakAuthenticationToken.class.isAssignableFrom(aClass);
	}

	@SuppressWarnings("unchecked")
	public String getToken(Object userPrincipal) {
		String accessToken = null;
		if (null != userPrincipal) {
			if (userPrincipal instanceof KeycloakPrincipal) {
				LOGGER.debug("Inside Keycloak Security Contect pricipal");
				KeycloakPrincipal<KeycloakSecurityContext> kp = (KeycloakPrincipal<KeycloakSecurityContext>) userPrincipal;
				accessToken = kp.getKeycloakSecurityContext().getTokenString();
				LOGGER.debug("Access Token Generated :::  {} ", accessToken);
			}
		}
		return accessToken;
	}

}
