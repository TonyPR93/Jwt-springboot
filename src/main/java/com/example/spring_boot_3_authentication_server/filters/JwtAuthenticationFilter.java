package com.example.spring_boot_3_authentication_server.filters;

import java.io.IOException;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.spring_boot_3_authentication_server.services.JwtService;
import com.example.spring_boot_3_authentication_server.services.UserService;

import ch.qos.logback.core.util.StringUtil;
import io.micrometer.common.lang.NonNull;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
/**
 * OncePerRequestFilter					Classe abstraite			Spring Web
 * SecurityContextHolder				Contexte de sécurité		Spring Security
 * UserDetails, UserDetailsService		Interfaces					Spring Security
 * UsernamePasswordAuthenticationToken	Classe d’authentification	Spring Security
 * WebAuthenticationDetailsSource		Détails techniques			Spring Security
 * StringUtils							Utilitaire chaîne			Apache Commons Lang
 * jwtService							Service personnalisé		Ton code (à créer ou déjà fait)
 * userService							Service personnalisé		Ton code (utilise un UserRepository)
 * 
 * Ce filtre a pour but de :
 * Intercepter chaque requête HTTP,
 * Vérifier si elle contient un JWT valide,
 * Extraire l'utilisateur du token,
 * L’authentifier dans Spring Security,
 * Et laisser passer la requête.
 * 
 * Même si tu as déjà un JWT, Spring Security nécessite que l'utilisateur soit authentifié dans son propre contexte de sécurité 
 * afin de pouvoir appliquer les règles de sécurité et de gérer les autorisations. 
 * Le filtre transforme donc le JWT en un objet que Spring peut comprendre et utilise ce dernier pour 
 * appliquer l'authentification et les autorisations de manière uniforme tout au long de la requête.
 * **/
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter{
	private final JwtService jwtService;
	private final UserService userService;
	@Override
	protected void doFilterInternal(@NonNull HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		// TODO Auto-generated method stub
		final String authHeader = request.getHeader("Authorization");
		final String jwt;
		final String userEmail;
		
		if (StringUtils.isEmpty(authHeader) || !StringUtils.startsWith(authHeader, "Bearer ")) {
			filterChain.doFilter(request, response);
			return;
		}
		
		 jwt = authHeader.substring(7);
	      log.debug("JWT - {}", jwt.toString());
	      userEmail = jwtService.extractUserName(jwt);
	      if (StringUtils.isNotEmpty(userEmail) && SecurityContextHolder.getContext().getAuthentication() == null) {
	          UserDetails userDetails = userService.userDetailsService().loadUserByUsername(userEmail);
	          if (jwtService.isTokenValid(jwt, userDetails)) {
	            log.debug("User - {}", userDetails);
	            SecurityContext context = SecurityContextHolder.createEmptyContext();
	            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
	                    userDetails, null, userDetails.getAuthorities());
	            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
	            context.setAuthentication(authToken);
	            SecurityContextHolder.setContext(context);
	          }
	      }
	      filterChain.doFilter(request, response);
	  }
	}