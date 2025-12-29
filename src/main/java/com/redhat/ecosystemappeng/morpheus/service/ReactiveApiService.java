package com.redhat.ecosystemappeng.morpheus.service;

import com.redhat.ecosystemappeng.morpheus.client.ReactiveApiClient;
import com.redhat.ecosystemappeng.morpheus.model.reactive.SimpleRequest;
import com.redhat.ecosystemappeng.morpheus.model.reactive.SimpleResponse;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.rest.client.inject.RestClient;
import org.jboss.logging.Logger;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * Service that demonstrates non-blocking reactive API calls using quarkus-rest-client-reactive.
 * Sends multiple POST requests in parallel to a global endpoint.
 */
@ApplicationScoped
public class ReactiveApiService {

    private static final Logger LOG = Logger.getLogger(ReactiveApiService.class);

    @Inject
    @RestClient
    ReactiveApiClient reactiveApiClient;

    /**
     * Sends multiple POST requests in parallel using reactive streams (non-blocking).
     * All requests are sent concurrently to the configured endpoint.
     *
     * @param message The message to send in each request
     * @param count The number of POST requests to send (default: 5)
     * @return Uni containing aggregated response from all requests
     */
    public Uni<SimpleResponse> sendMultiplePostRequests(String message, int count) {
        long startTime = System.currentTimeMillis();

        LOG.infof("Starting %d parallel POST requests with message: %s", count, message);

        // Create multiple POST requests in parallel using Uni.combine()
        // This demonstrates non-blocking concurrent execution
        // Convert CompletionStage to Uni for reactive processing
        List<Uni<Response>> requestUnis = IntStream.range(1, count + 1)
                .mapToObj(i -> {
                    SimpleRequest request = new SimpleRequest(message, i);
                    return Uni.createFrom().completionStage(reactiveApiClient.sendPostRequest(request))
                            .onFailure().recoverWithItem(throwable -> {
                                LOG.warnf(throwable, "Request %d failed: %s", i, throwable.getMessage());
                                return Response.serverError()
                                        .entity("{\"error\":\"" + throwable.getMessage() + "\"}")
                                        .build();
                            });
                })
                .collect(Collectors.toList());

        return Uni.join().all(requestUnis)
                .andCollectFailures()
                .map(list -> {
                    long executionTime = System.currentTimeMillis() - startTime;
                    LOG.infof("All %d POST requests completed in %d ms", count, executionTime);

                    List<SimpleResponse.ResponseItem> responseItems = new ArrayList<>();
                    for (int i = 0; i < list.size(); i++) {
                        Response response = (Response) list.get(i);
                        String status = response.getStatus() == 200 ? "success" : "error";
                        Object data = response.hasEntity() ? response.readEntity(Object.class) : null;
                        responseItems.add(new SimpleResponse.ResponseItem(i + 1, status, data));
                    }

                    return new SimpleResponse(responseItems, executionTime, count);
                })
                .onFailure().invoke(throwable -> {
                    LOG.errorf(throwable, "Error sending POST requests: %s", throwable.getMessage());
                });
    }
}

