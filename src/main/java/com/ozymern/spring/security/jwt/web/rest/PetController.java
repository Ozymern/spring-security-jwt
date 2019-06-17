package com.ozymern.spring.security.jwt.web.rest;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ozymern.spring.security.jwt.models.entities.Pet;
import com.ozymern.spring.security.jwt.models.services.PetService;

@RestController
@RequestMapping(PetController.URI_BASE)
public class PetController {

	public static final String URI_BASE = "/api/v1";

	@Autowired
	private PetService petService;

	@GetMapping("/pets")
	@PreAuthorize("hasAuthority('ROLE_USER')")
	public List<Pet> listAllUser() {
		return petService.findAllPets();
	}

	@GetMapping("/pets/{id}")
	@PreAuthorize("hasAuthority('ROLE_USER')")
	public ResponseEntity<Pet> getPets(@PathVariable("id") Long id) {

		Pet pet = petService.findPetById(id);

		return (pet != null) ? new ResponseEntity<>(pet, HttpStatus.OK) : new ResponseEntity<>(HttpStatus.NOT_FOUND);
	}

	@PutMapping("/pets/{id}")
	// @PreAuthorize("hasAuthority('ROLE_ADMIN')")
	public ResponseEntity<Pet> updatePet(@PathVariable Long id, @RequestBody Pet pet) {

		if (petService.updatePet(pet, id) != null) {
			return new ResponseEntity<>(pet, HttpStatus.OK);
		} else {
			return new ResponseEntity<>(HttpStatus.NOT_FOUND);
		}

	}

	@PostMapping("/pets/{id}")
	@PreAuthorize("hasAuthority('ROLE_ADMIN')")
	public ResponseEntity<Pet> createPet(@PathVariable Long id, @RequestBody Pet pet) {

		
		return new ResponseEntity<>(petService.createPetPet(pet), HttpStatus.CREATED);

	}

	@DeleteMapping("/pets/{id}")
	@PreAuthorize("hasAuthority('ROLE_ADMIN')")
	public ResponseEntity<Pet> deletePet(@PathVariable Long id) {

		Pet petDelete = petService.findPetById(id);

		if (petDelete != null) {

			petService.deletePet(petService.findPetById(id));
			return new ResponseEntity<>(petDelete, HttpStatus.OK);

		} else {
			return new ResponseEntity<>(HttpStatus.NOT_FOUND);
		}

	}
}