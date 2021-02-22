package com.ozymern.spring.security.jwt.security;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.ozymern.spring.security.jwt.io.Login;
import com.ozymern.spring.security.jwt.io.Recaptchav3Response;
import com.ozymern.spring.security.jwt.models.services.ICaptchaService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ozymern.spring.security.jwt.models.entities.User;
import com.ozymern.spring.security.jwt.models.services.JWTService;


//los filtros se encargan de realizar la autentificacion, es un filtro que se ejecuta antes de llamar al RestControllador
//este filtro se va a ocuopar solamente cuando coincida con con la ruta AntPathRequestMatcher("/login", "POST")
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private AuthenticationManager authenticationManager;
	private JWTService jwtService;
	private ICaptchaService iCaptchaService;

	// en los filtros no se pueden inyectar objetos con @Autowired
	public JWTAuthenticationFilter(AuthenticationManager authenticationManager, JWTService jwtService, ICaptchaService iCaptchaService) {

		// customizando el path para el login
		setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/api/login", "POST"));
		this.authenticationManager = authenticationManager;
		this.jwtService= jwtService;
		this.iCaptchaService=iCaptchaService;
	}

	// este metodo trabaja de la mano con nuestro proveedor de autentificacion
	// (UserDetailsSErvice)
	// este metodo intenta realizar la autentificacion
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		String username = obtainUsername(request);
		String password = obtainPassword(request);



		if (username != null && password != null) {
			// vemos los valores que estamos recibiendo en una api rest
			logger.info("user filter Authentication data " + username);
			logger.info("password filter Authentication data " + password);
		} else {
			// convertir los datos en raw que vienen en json en objectos java
			Login user = null;
			
			//los datos en raw con formato json vienen en el request.getInputStream()
			//para convertir ocupamos ObjectMapper().readValue

			try {
				user = new ObjectMapper().readValue(request.getInputStream(), Login.class);
				// Asignar los valores trasformados al user y password
				username = user.getUsername();
				password = user.getPassword();

				ResponseEntity<Recaptchav3Response> recaptchav3Response=iCaptchaService.processResponse(user.getRecaptchaToken());
				if(!recaptchav3Response.getStatusCode().is2xxSuccessful()){
					logger.error("error  recaptchav3 http !=200");
					throw new AuthenticationServiceException("error recaptchav3");
				}else if(!recaptchav3Response.getBody().isSuccess()){
					logger.error("error  recaptchav3 != success");
					throw new AuthenticationServiceException("error recaptchav3");
				}

				logger.info("user filter Authentication raw " + username);
				logger.info("password filter Authentication raw " + password);

			} catch (JsonParseException e) {
				logger.error("error :"+e.getMessage() );
			} catch (JsonMappingException e) {

				logger.error("error :"+e.getMessage() );
			} catch (IOException e) {
				logger.error("error :"+e.getMessage() );
			}

		}

		username = username.trim();
		// contenedor de las las credenciales, lo instanciamos con el username y el
		// password
		UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);

		// devolvemos una instancia de AuthenticationManager con las coredenciales, este
		// token se maneja de forma interna
		return authenticationManager.authenticate(authToken);
	}

	
	//metodo que se implementa cuando la autentificacion es un exito
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		
		String token = jwtService.create(authResult);
		
		//pasamos el token en la cabezera de la respuesta, Bearer es un standar
		response.addHeader("Authorization", "Bearer "+token);
		
	
		
		//agregamos datos adicionales que se pasaran 
		Map<String , Object>body = new HashMap<>();
		body.put("token", token);
		body.put("user", authResult.getPrincipal());
		body.put("message", String.format("Hola %s, has iniciado sesion con exito", authResult.getName()));
		body.put("authorities",authResult.getAuthorities());
		
		//pasar los datos a la repuesta, trasformamos el obeto map a json
		response.getWriter().write(new ObjectMapper().writeValueAsString(body));
		
//		los claims es para agregar datos al token, al jwt, mientras que el map es para pasar datos en la respuesta, 
//		es decir al json que retorna el backend! dentro del map se incluye el token jwt!
		
		response.setStatus(200);
		response.setContentType("application/json");
		
	}

	//metodo para lanzar un error cuando no se esta autenticado
	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException {

		//guardaremos el mensaje de error
		Map<String , Object>body = new HashMap<>();

		if(failed.getMessage().equalsIgnoreCase("error recaptchav3")){
			body.put("message","error recaptchav3 google");
			//mensaje de error original que maneja spring Exeption
			body.put("error", failed.getMessage());
		}else{
			body.put("message","Error de autenticacion: username o password incorrecto");
			//mensaje de error original que maneja spring Exeption
			body.put("error", failed.getMessage());
		}

		
		//pasar los datos a la repuesta, trasformamos el obeto map a json
		response.getWriter().write(new ObjectMapper().writeValueAsString(body));
		//401 prohibido, 403 manejo de roles autorizacion
		response.setStatus(401);
		response.setContentType("application/json");
		
		
	}


}
