package com.ozymern.spring.security.jwt.security;

import org.springframework.transaction.annotation.Transactional;

import com.ozymern.spring.security.jwt.models.entities.Role;
import com.ozymern.spring.security.jwt.models.entities.User;
import com.ozymern.spring.security.jwt.models.repositories.UserRepository;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

	@Autowired
	private UserRepository userRepository;

	private Logger logger = LoggerFactory.getLogger(UserDetailsServiceImpl.class);

	// metodo para cargar al usuario junto con sus roles
	@Override
	@Transactional(readOnly = true)
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

		User user = userRepository.findByUsername(username);



		if (user == null) {
			logger.error("Error login: no existe el usuario: " + username + " en la base de datos");
			throw new UsernameNotFoundException("email " + username + " no existe!");

		}
		

		// optener los roles de usuario GrantedAuthority= es una interfaz que sirve para
		// obtener los privilegio o persimos
		List<GrantedAuthority> authorities = new ArrayList<>();

		// asigno el rol de mi usuario a la interfaz authorities
		for (Role role : user.getRoles()) {
			authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getRole().toUpperCase()));
		}

		// con java 8
		user.getRoles().forEach(role -> {
			authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getRole().toUpperCase()));
		});

		// valido si la authorities tienes roles asignados
		if (authorities.isEmpty()) {
			logger.error("Error login: no existe el usuario " + username + " no tiene roles asignados");
			throw new UsernameNotFoundException(
					"Error login: no existe el usuario " + username + " no tiene roles asignados");
		}
		
		
		//return new User(username, user.getPassword(), user.getEnabled(), true, true, true, authorities);
		
		
		
		return new UserPrincipal(user);

	}

}
