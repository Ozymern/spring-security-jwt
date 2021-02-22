package com.ozymern.spring.security.jwt.models.entities;

import lombok.Data;
import lombok.ToString;

import java.io.Serializable;
import java.util.List;

import javax.persistence.*;

@Entity
@Table(name = "user")
@Data
@ToString
public class User implements Serializable {

	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "user_id")
	private Long id;
	@Column(length = 30, unique = true)
	private String username;

	@Column(length = 30, unique = true)
	private String email;

	@Column(length = 60)
	private String password;

	private Boolean enabled;


	@ManyToMany(cascade = CascadeType.ALL)
    @JoinTable(name = "user_role", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"))
    private List<Role> roles;




}
