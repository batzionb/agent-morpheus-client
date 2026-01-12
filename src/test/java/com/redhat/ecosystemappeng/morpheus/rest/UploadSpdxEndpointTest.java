package com.redhat.ecosystemappeng.morpheus.rest;

import static org.hamcrest.Matchers.*;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import io.restassured.RestAssured;
import io.restassured.http.ContentType;

import java.io.File;

/**
 * End-to-end test for the SPDX upload API endpoint.
 * 
 * This test assumes the service is running in a separate process.
 * Set the BASE_URL environment variable to point to the running service,
 * e.g., BASE_URL=http://localhost:8080
 * 
 * If BASE_URL is not set, tests will be skipped.
 */
@EnabledIfEnvironmentVariable(named = "BASE_URL", matches = ".*")
class UploadSpdxEndpointTest {

    private static final String BASE_URL = System.getenv("BASE_URL");
    private static final String API_BASE = BASE_URL != null ? BASE_URL : "http://localhost:8080";
    private static final String TEST_SBOM_FILE = "src/test/resources/devservices/spdx-sboms/gitops-1.19.json";
    private static final String TEST_VULN_ID = "CVE-2021-4238";

    @Test
    void testUpload_ValidFileAndVulnerabilityId() {
        File sbomFile = new File(TEST_SBOM_FILE);
        RestAssured.baseURI = API_BASE;
        
        // Upload the file and verify product was created
        String productId = RestAssured.given()
            .contentType(ContentType.MULTIPART)
            .multiPart("file", sbomFile)
            .queryParam("vulnerabilityId", TEST_VULN_ID)
            .when()
            .post("/api/v1/products/upload-spdx")
            .then()
            .statusCode(202)
            .contentType(ContentType.JSON)
            .body("productId", notNullValue())
            .extract()
            .path("productId");
        
        assert productId != null : "Product ID should not be null";
        
        // Verify product was created and contains CPE in metadata
        RestAssured.given()
            .when()
            .get("/api/v1/products/" + productId)
            .then()
            .statusCode(200)
            .contentType(ContentType.JSON)
            .body("data.metadata.cpe", equalTo("cpe:/a:redhat:openshift_gitops:1.19::el8"));
    }
}

