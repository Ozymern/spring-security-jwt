package com.ozymern.spring.security.jwt.config;

import com.ozymern.spring.security.jwt.models.services.ICaptchaService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.ozymern.spring.security.jwt.models.services.JWTService;
import com.ozymern.spring.security.jwt.security.JWTAuthenticationFilter;
import com.ozymern.spring.security.jwt.security.JWTAuthorizationFilter;
import com.ozymern.spring.security.jwt.security.UserDetailsServiceImpl;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;


//anotacion para habilitar la anotacione @secured (securedEnabled=true) y prePostEnabled=true  	@PreAuthorize
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
@Configuration
class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;

	@Autowired
	private UserDetailsServiceImpl userDetailsService;
	
	@Autowired
	private JWTService jwtService;

	@Autowired
	private ICaptchaService iCaptchaService;


	// para las autorizaciones
	@Override
	protected void configure(HttpSecurity httpSecurity) throws Exception {

		//configuraciones
		httpSecurity		
				//ya que ocuparemos de token jwt, desabilitamos el token de csrf que nos entrega springboot y thymeleaf por defecto
				.csrf().disable()
				.authorizeRequests()
				//uri que permito que se vean sin autenticar
                .antMatchers(HttpMethod.GET,"/api/v1/pets").permitAll()
                .anyRequest()
                .authenticated()
                // llamamos a nuestro filtro y le pasamos el AuthenticationManager que tiene la clase WebSecurityConfigurerAdapte por herencia atraves del metodo authenticationManager()
                .and()
				.cors()
				.and()
                .addFilter(new JWTAuthenticationFilter(authenticationManager(),jwtService,iCaptchaService))
                .addFilter(new JWTAuthorizationFilter(authenticationManager(), jwtService))

    			//deshabilitamos el uso de sesiones, no guarda los datos en la sesiones  
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
	}

	@Bean
	public CorsFilter corsFilter() {
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		CorsConfiguration config = new CorsConfiguration();
		config.setAllowCredentials(true);
		config.addAllowedOrigin("*");
		config.addAllowedHeader("*");
		config.addAllowedMethod("*");
		source.registerCorsConfiguration("/**", config);
		return new CorsFilter(source);
	}

	@Autowired
	public void configurerGlobal(AuthenticationManagerBuilder auth) throws Exception {

		// CON JPA
		auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);

	}

}
