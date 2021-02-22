package com.ozymern.spring.security.jwt.io;

import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class Login {
    private String username;
    private String password;
    private String recaptchaToken;
}
