package com.ozymern.spring.security.jwt.io;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class Recaptchav3Response {
    @JsonProperty( "success" )
    private boolean success;

    @JsonProperty( "score" )
    private double score;

    @JsonProperty( "action" )
    private String action;

    @JsonProperty( "challenge_ts" )
    private Object timestamp;

    @JsonProperty( "hostname" )
    private String hostname;

    @JsonProperty( "error-codes" )
    private Object errors;



}
