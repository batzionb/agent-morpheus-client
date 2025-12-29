package com.redhat.ecosystemappeng.morpheus.model.reactive;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class SimpleRequest {
    public String message;
    public int id;

    public SimpleRequest() {
    }

    public SimpleRequest(String message, int id) {
        this.message = message;
        this.id = id;
    }
}

