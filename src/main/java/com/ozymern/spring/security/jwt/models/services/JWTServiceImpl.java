package com.ozymern.spring.security.jwt.models.services;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.util.Base64Utils;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ozymern.spring.security.jwt.security.SimpleGrantedAuthorityMixin;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Service
public class JWTServiceImpl implements JWTService {
	
	public static final String KEY_SECRET = Base64Utils.encodeToString("clavesecreta".getBytes());
	
	public static final long EXPIRATION_DATE=3600000L;
	
	public static final String TOKEN_PREFIX="Bearer ";
	
	public static final String HEADER_STRING="authorities";
	
	
	@Override
	public String create(Authentication authResult) throws JsonProcessingException {

		// creamos las claims que son parametros extras
		Claims claims = Jwts.claims();
		// agregamos los roles, que estan en authResult.getAuthorities() y que los
		// devolvemos en formato json con (new ObjectMapper().writeValueAsString
		claims.put(HEADER_STRING, new ObjectMapper().writeValueAsString(authResult.getAuthorities()));

		String token = Jwts.builder()
				// agregamos las clains
				.setClaims(claims)
				// obtenemos el nombre del usuario
				.setSubject(authResult.getName())
				// tipo de algoritmo y clave secreta
				.signWith(SignatureAlgorithm.HS512, KEY_SECRET.getBytes())
				// fecha de creacion
				.setIssuedAt(new Date())
				// fecha de expiracion, fecha actual y fecha en el futuro
				.setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_DATE))
				// compactamos nuestro token
				.compact();

		return token;

	}

	@Override
	public boolean validateToken(String token) {

		try {
			getClains(token);

			return true;

		} catch (JwtException | IllegalArgumentException e) {
			return false;

		}
	}

	@Override
	public Claims getClains(String token) {

		Claims claims = null;
		claims = Jwts.parser()
				// AGREGAMOS LA LLAVE SECRETA
				.setSigningKey(KEY_SECRET.getBytes())
				// obtenemos el token, y quitamos el prefijo Bearer, getBody, para optener los
				// datos del token
				.parseClaimsJws(resolveToken(token)).getBody();
		return claims;
	}

	@Override
	public String getUsername(String token) {

		return getClains(token).getSubject();
	}

	@Override
	public Collection<? extends GrantedAuthority> getRoles(String token)
			throws JsonParseException, JsonMappingException, IOException {
		
		//los authorities vienen en el map que creamos en el JWTAuthentication con la key authorities
		Object roles = getClains(token).get(HEADER_STRING);
		// convierte el json en objeto user, los roles vienen en json lo convertimos en
		// String, pasamos de segundo parametro una implementacion de GrantedAuthority
		// pero como es una collecion, pasamos un array
		// finalmente convertimos un array en una lista de tipo collection con
		// Arrays.asList
		// pcuparemos una clase mixin que sirve para mezclar clases, en este caso
		// opcuparemos una implementacion de SimpleGrantedAuthority con constructor

		Collection<? extends GrantedAuthority> authorities = Arrays.asList(new ObjectMapper()
				// agrego el mixin, primer paramneto es la clase a la que queremos convertir y
				// el segundo es el mixin
				.addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class)
				.readValue(roles.toString().getBytes(), SimpleGrantedAuthority[].class));
		return authorities;
	}

	@Override
	public String resolveToken(String token) {

		if (token != null && token.startsWith(TOKEN_PREFIX)) {
			return token.replace(TOKEN_PREFIX, "");
		} else {
			return null;
		}

	}

}
