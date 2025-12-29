package com.redhat.ecosystemappeng.morpheus.client;

import com.redhat.ecosystemappeng.morpheus.model.reactive.SimpleRequest;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.rest.client.inject.RegisterRestClient;

import java.util.concurrent.CompletionStage;

/**
 * Reactive REST client for testing non-blocking API calls.
 * Sends POST requests to a global endpoint.
 */
@RegisterRestClient(configKey = "reactive-api")
@Produces(MediaType.APPLICATION_JSON)
public interface ReactiveApiClient {

    /**
     * Sends a POST request to the configured endpoint
     */
    @POST
    @Path("/posts")
    @Consumes(MediaType.APPLICATION_JSON)
    CompletionStage<Response> sendPostRequest(SimpleRequest request);
}

