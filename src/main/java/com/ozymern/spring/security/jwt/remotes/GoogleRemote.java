package com.ozymern.spring.security.jwt.remotes;


import com.ozymern.spring.security.jwt.io.Recaptchav3Response;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;



@FeignClient(name="google-remote", url="${google.server}")
public interface GoogleRemote {

    @RequestMapping(method = RequestMethod.GET, value = "/recaptcha/api/siteverify", consumes = "application/json")
     ResponseEntity<Recaptchav3Response> siteverify(@RequestParam(value = "secret") String secret,@RequestParam (value = "response")String response);
}