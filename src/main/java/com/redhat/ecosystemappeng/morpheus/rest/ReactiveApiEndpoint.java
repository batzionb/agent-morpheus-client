package com.redhat.ecosystemappeng.morpheus.rest;

import com.redhat.ecosystemappeng.morpheus.model.reactive.SimpleResponse;
import com.redhat.ecosystemappeng.morpheus.service.ReactiveApiService;
import io.smallrye.mutiny.Uni;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponses;
import org.eclipse.microprofile.openapi.annotations.security.SecurityRequirement;
import org.jboss.logging.Logger;

/**
 * REST endpoint demonstrating non-blocking reactive API calls using quarkus-rest-client-reactive.
 * Sends multiple POST requests in parallel to a global endpoint.
 */
@SecurityRequirement(name = "jwt")
@Path("/reactive-api")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class ReactiveApiEndpoint {

    private static final Logger LOG = Logger.getLogger(ReactiveApiEndpoint.class);

    @Inject
    ReactiveApiService reactiveApiService;

    @POST
    @Operation(
        summary = "Send multiple POST requests in parallel (reactive)",
        description = "Demonstrates non-blocking reactive API calls. Sends multiple POST requests in parallel using Uni and returns aggregated results."
    )
    @APIResponses({
        @APIResponse(
            responseCode = "200",
            description = "Successfully sent all POST requests in parallel",
            content = @Content(
                schema = @Schema(implementation = SimpleResponse.class)
            )
        ),
        @APIResponse(
            responseCode = "500",
            description = "Error sending one or more requests"
        )
    })
    public Uni<Response> sendMultiplePosts(
        @Parameter(description = "Message to send in each request", example = "test message")
        @QueryParam("message") @DefaultValue("Hello from reactive client") String message,
        @Parameter(description = "Number of POST requests to send", example = "5")
        @QueryParam("count") @DefaultValue("5") int count
    ) {
        LOG.infof("Received request to send %d POST requests with message: %s", count, message);
        
        return reactiveApiService.sendMultiplePostRequests(message, count)
                .map(simpleResponse -> {
                    LOG.infof("Successfully sent %d POST requests in %d ms", 
                            simpleResponse.totalRequests, simpleResponse.totalExecutionTimeMs);
                    return Response.ok(simpleResponse).build();
                })
                .onFailure().recoverWithItem(throwable -> {
                    LOG.errorf(throwable, "Failed to send POST requests: %s", throwable.getMessage());
                    return Response.serverError()
                            .entity("{\"error\":\"" + throwable.getMessage() + "\"}")
                            .build();
                });
    }
}

