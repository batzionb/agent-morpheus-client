package com.redhat.ecosystemappeng.morpheus.rest;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import org.jboss.logging.Logger;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URL;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.notNullValue;

@QuarkusTest
public class ProductEndpointTest {

    private static final Logger LOG = Logger.getLogger(ProductEndpointTest.class);

    private String formatFullResponse(Response response) {
        StringBuilder responseDetails = new StringBuilder();
        responseDetails.append("\n=== FULL RESPONSE DETAILS ===\n");
        responseDetails.append("Status Code: ").append(response.getStatusCode()).append("\n");
        responseDetails.append("Status Line: ").append(response.getStatusLine()).append("\n");
        responseDetails.append("Content Type: ").append(response.getContentType()).append("\n");
        responseDetails.append("\n--- Response Headers ---\n");
        response.getHeaders().forEach(header -> 
            responseDetails.append(header.getName()).append(": ").append(header.getValue()).append("\n")
        );
        responseDetails.append("\n--- Response Body ---\n");
        responseDetails.append(response.getBody().asString());
        responseDetails.append("\n==============================\n");
        return responseDetails.toString();
    }

    @Test
    public void testCreateProductFromSpdxFile() {
        try {
            // Load the test file from classpath
            URL resource = getClass().getClassLoader().getResource("spdx_sboms/gitops-1.19.json");
            File spdxFile;
            
            if (resource != null) {
                spdxFile = new File(resource.getFile());
            } else {
                // Fallback to file system path if classpath resource not found
                spdxFile = new File("src/test/resources/spdx_sboms/gitops-1.19.json");
            }
            
            Response response = given()
                .contentType(ContentType.MULTIPART)
                .multiPart("file", spdxFile)
                .when()
                .post("/api/v1/product/new");
            
            try {
                response.then()
                    .statusCode(202)
                    .contentType(ContentType.JSON)
                    .body("productId", notNullValue());
            } catch (AssertionError e) {
                // Log complete response details when assertion fails
                LOG.errorf("Test assertion failed.%s", formatFullResponse(response));
                
                StringWriter sw = new StringWriter();
                PrintWriter pw = new PrintWriter(sw);
                e.printStackTrace(pw);
                String stackTrace = sw.toString();
                LOG.errorf("Full stack trace:%n%s", stackTrace);
                throw e;
            }
        } catch (Exception e) {
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            e.printStackTrace(pw);
            String stackTrace = sw.toString();
            LOG.errorf("Test failed with exception: %s%nFull stack trace:%n%s", e.getMessage(), stackTrace);
            throw e;
        }
    }
}

