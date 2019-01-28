package com.ozymern.spring.security.jwt.models.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.ozymern.spring.security.jwt.models.entities.Pet;

public interface PetRepository extends JpaRepository<Pet, Long>{

}
