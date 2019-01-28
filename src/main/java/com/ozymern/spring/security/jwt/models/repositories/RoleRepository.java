package com.ozymern.spring.security.jwt.models.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.ozymern.spring.security.jwt.models.entities.Role;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

}
