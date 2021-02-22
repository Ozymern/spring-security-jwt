package com.ozymern.spring.security.jwt.models.services;

import com.ozymern.spring.security.jwt.io.Recaptchav3Response;
import org.springframework.http.ResponseEntity;

public interface ICaptchaService {

     ResponseEntity<Recaptchav3Response> processResponse(String recaptchaToken);
}
