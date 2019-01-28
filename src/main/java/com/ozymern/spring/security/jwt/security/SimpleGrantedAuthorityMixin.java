package com.ozymern.spring.security.jwt.security;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public abstract class SimpleGrantedAuthorityMixin {

	
	@JsonCreator
	//anotacion que sirve para indicar que este es el constructor por defecto que se creen los objetos authorities a partir del json
	//@JsonProperty se inyecta el valor por defecto authority valor que se crea en el map de JWTAuthenticationFilter
	public SimpleGrantedAuthorityMixin(@JsonProperty("authority") String role) {
	
	}
	
	
	

}
