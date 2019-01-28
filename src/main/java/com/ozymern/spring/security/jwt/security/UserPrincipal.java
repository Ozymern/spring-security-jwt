package com.ozymern.spring.security.jwt.security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.ozymern.spring.security.jwt.models.entities.User;

public class UserPrincipal implements UserDetails {


	private static final long serialVersionUID = 1L;
	
	private final User user;

	public UserPrincipal(User user) {
		this.user = user;
	}

	//

	@Override
	public String getUsername() {
		return user.getUsername();
	}

	@Override
	public String getPassword() {
		return user.getPassword();
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		// optener los roles de usuario GrantedAuthority= es una interfaz que sirve para
		// obtener los privilegio o persimos
		List<GrantedAuthority> authorities = new ArrayList<>();

		// con java 8
		user.getRoles().forEach(role -> {
			authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getRole().toUpperCase()));
		});
		return authorities;
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}

	public User getUser() {
		return user;
	}

	@Override
	public String toString() {
		return "UserPrincipal [user=" + user + "]";
	}

}
