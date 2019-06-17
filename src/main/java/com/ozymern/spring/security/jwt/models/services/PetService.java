package com.ozymern.spring.security.jwt.models.services;

import java.util.List;

import com.ozymern.spring.security.jwt.models.entities.Pet;

public interface PetService {

	public List<Pet> findAllPets();
	public Pet findPetById(Long id);
	public Pet updatePet(Pet pet, Long id);
	public void deletePet(Pet pet);
	public Pet createPetPet(Pet pet);
}


