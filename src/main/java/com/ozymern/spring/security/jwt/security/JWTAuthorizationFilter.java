package com.ozymern.spring.security.jwt.security;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.ozymern.spring.security.jwt.models.services.JWTService;

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {
	
	private JWTService jwtService;

	public JWTAuthorizationFilter(AuthenticationManager authenticationManager, JWTService jwtService) {
		super(authenticationManager);
		
		this.jwtService=jwtService;

	}

	// metodo que se ejecutara en toda request donde en la cabecera tenga
	// Authorization y sea del tipo Bearer, para authorizar el token
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		String header = request.getHeader("Authorization");

		if (header == null || !header.startsWith("Bearer ")) {
			// sigue el flujo
			chain.doFilter(request, response);
			return;
		}

	
		
		UsernamePasswordAuthenticationToken authentication=null;
		
		 
		if (jwtService.validateToken(header)) {
		
			//inicio de session
			authentication = new UsernamePasswordAuthenticationToken(jwtService.getUsername(header), null,  jwtService.getRoles(header));
		}
		
		// se encarga de manejar el contexto de seguridad, para que autentique al usuario dentro de la solicitud del request
		SecurityContextHolder.getContext().setAuthentication(authentication);
		
		//continuamos con la cadena de ejecucion del request
		chain.doFilter(request, response);

	}

}
