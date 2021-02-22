package com.ozymern.spring.security.jwt.models.services;

import com.ozymern.spring.security.jwt.io.Recaptchav3Response;
import com.ozymern.spring.security.jwt.remotes.GoogleRemote;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
public class CaptchaService implements ICaptchaService{


    @Value("${google.recaptcha.key.secret}")
    private String secret;

    @Autowired
    private GoogleRemote googleRemote;


    @Override
    public ResponseEntity<Recaptchav3Response> processResponse(String recaptchaToken) {
      return   googleRemote.siteverify(this.secret,recaptchaToken);
    }
}
