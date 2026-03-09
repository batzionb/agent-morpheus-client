package com.redhat.ecosystemappeng.morpheus.rest;

import static org.hamcrest.Matchers.*;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import io.restassured.RestAssured;
import io.restassured.http.ContentType;

import java.io.File;

/**
 * End-to-end test for the parse-spdx API endpoint.
 *
 * Set BASE_URL to the running service (e.g. BASE_URL=http://localhost:8080).
 * If BASE_URL is not set, tests are skipped.
 */
@EnabledIfEnvironmentVariable(named = "BASE_URL", matches = ".*")
class ParseSpdxEndpointTest {

    private static final String BASE_URL = System.getenv("BASE_URL");
    private static final String API_BASE = BASE_URL != null ? BASE_URL : "http://localhost:8080";
    private static final String TEST_SBOM_FILE = "src/test/resources/devservices/spdx-sboms/gitops-1.19.json";
    private static final String SPDX_WITH_UNSUPPORTED = "src/test/resources/devservices/spdx-sboms/spdx-with-unsupported-component.json";
    private static final String INVALID_SPDX_DIR = "src/test/resources/devservices/spdx-sboms/invalid";

    @Test
    void testParseSpdx_ValidFile_Returns200WithParseResult() {
        File sbomFile = new File(TEST_SBOM_FILE);
        RestAssured.baseURI = API_BASE;
        RestAssured.given()
            .contentType(ContentType.MULTIPART)
            .multiPart("file", sbomFile)
            .when()
            .post("/api/v1/products/parse-spdx")
            .then()
            .statusCode(200)
            .contentType(ContentType.JSON)
            .body("productInfo", notNullValue())
            .body("productInfo.spdxId", notNullValue())
            .body("productInfo.name", notNullValue())
            .body("productInfo.version", notNullValue())
            .body("components", notNullValue())
            .body("unsupportedComponents", notNullValue());
    }

    @Test
    void testParseSpdx_ValidFileWithUnsupportedComponent_ReturnsComponentsAndUnsupported() {
        File sbomFile = new File(SPDX_WITH_UNSUPPORTED);
        RestAssured.baseURI = API_BASE;
        RestAssured.given()
            .contentType(ContentType.MULTIPART)
            .multiPart("file", sbomFile)
            .when()
            .post("/api/v1/products/parse-spdx")
            .then()
            .statusCode(200)
            .contentType(ContentType.JSON)
            .body("productInfo.name", equalTo("test-product"))
            .body("components", hasSize(1))
            .body("components[0].purl", startsWith("pkg:oci/"))
            .body("unsupportedComponents", hasSize(1))
            .body("unsupportedComponents[0].name", equalTo("maven-lib"))
            .body("unsupportedComponents[0].purl", equalTo("pkg:maven/org.example/maven-lib@2.0"));
    }

    @Test
    void testParseSpdx_MissingFile_Returns400WithFileError() {
        RestAssured.baseURI = API_BASE;
        RestAssured.given()
            .contentType(ContentType.MULTIPART)
            .when()
            .post("/api/v1/products/parse-spdx")
            .then()
            .statusCode(400)
            .contentType(ContentType.JSON)
            .body("errors.file", notNullValue());
    }

    @Test
    void testParseSpdx_InvalidNoDescribes_Returns400WithFileError() {
        File sbomFile = new File(INVALID_SPDX_DIR, "spdx-no-describeby.json");
        RestAssured.baseURI = API_BASE;
        RestAssured.given()
            .contentType(ContentType.MULTIPART)
            .multiPart("file", sbomFile)
            .when()
            .post("/api/v1/products/parse-spdx")
            .then()
            .statusCode(400)
            .contentType(ContentType.JSON)
            .body("errors.file", equalTo("No DESCRIBES relationship found in SPDX document"));
    }

    @Test
    void testParseSpdx_InvalidProductPackageNotFound_Returns400WithFileError() {
        File sbomFile = new File(INVALID_SPDX_DIR, "spdx-describes-missing-package.json");
        RestAssured.baseURI = API_BASE;
        RestAssured.given()
            .contentType(ContentType.MULTIPART)
            .multiPart("file", sbomFile)
            .when()
            .post("/api/v1/products/parse-spdx")
            .then()
            .statusCode(400)
            .contentType(ContentType.JSON)
            .body("errors.file", equalTo("Product package not found: SPDXRef-Nonexistent-Product"));
    }

    @Test
    void testParseSpdx_InvalidProductNameMissing_Returns400WithFileError() {
        File sbomFile = new File(INVALID_SPDX_DIR, "spdx-product-no-name.json");
        RestAssured.baseURI = API_BASE;
        RestAssured.given()
            .contentType(ContentType.MULTIPART)
            .multiPart("file", sbomFile)
            .when()
            .post("/api/v1/products/parse-spdx")
            .then()
            .statusCode(400)
            .contentType(ContentType.JSON)
            .body("errors.file", containsString("Product name not found"));
    }
}
