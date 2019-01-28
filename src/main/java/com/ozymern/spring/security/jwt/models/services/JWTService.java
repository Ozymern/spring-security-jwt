package com.ozymern.spring.security.jwt.models.services;

import java.io.IOException;
import java.util.Collection;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;

import io.jsonwebtoken.Claims;

public interface JWTService {

	
	//metodo para crear el token
	public String create(Authentication authResult) throws JsonProcessingException;
	
	//metodo para validar el token
	public  boolean validateToken(String token);
	
	
	//metodo para optener las claims  token
	public Claims getClains(String token);
	
	//metodo para optener username
	public String getUsername(String token);
	
	//metodo para optener roles
	public Collection<? extends GrantedAuthority> getRoles(String token) throws JsonParseException, JsonMappingException, IOException;
	
	//metodo para quitar el Bearer y optener solo el token
	public String resolveToken(String token);
	
	
}
