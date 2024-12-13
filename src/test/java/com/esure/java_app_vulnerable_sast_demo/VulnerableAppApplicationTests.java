package com.esure.java_app_vulnerable_sast_demo;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.IOException;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.*;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootApplication
@SpringBootTest(classes = VulnerableAppApplication.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class VulnerableAppApplicationTests {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    private String getBaseUrl() {
        return "http://localhost:" + port;
    }

    // Test for SQL Injection
    @Test
    void testSqlInjection() {
        String payload = "' OR '1'='1";
        ResponseEntity<String> response = restTemplate.getForEntity(getBaseUrl() + "/search?query=" + payload, String.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(response.getBody().contains("username")); // Assuming usernames are returned
    }

    // Test for SSRF
    @Test
    void testSsrf() {
        String payload = "http://example.com";
        ResponseEntity<String> response = restTemplate.getForEntity(getBaseUrl() + "/fetch?url=" + payload, String.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    // Test for XSS
    @Test
    void testXss() {
        String payload = "<script>alert('XSS')</script>";
        ResponseEntity<String> response = restTemplate.getForEntity(getBaseUrl() + "/greet?name=" + payload, String.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(response.getBody().contains(payload)); // Reflected XSS payload in response
    }

    // Test for Insecure Deserialization
    @Test
    void testInsecureDeserialization() {
        byte[] payload = serializeObject("malicious payload");
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
        HttpEntity<byte[]> request = new HttpEntity<>(payload, headers);

        ResponseEntity<String> response = restTemplate.postForEntity(getBaseUrl() + "/deserialize", request, String.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    private byte[] serializeObject(Object obj) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(obj);
            return baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException("Serialization failed", e);
        }
    }

    // Test for Weak Cryptography
    @Test
    void testWeakCryptography() {
        String payload = "secret data";
        ResponseEntity<String> response = restTemplate.getForEntity(getBaseUrl() + "/encrypt?data=" + payload, String.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(response.getBody().contains("encrypted")); // Check response contains encrypted data
    }

    // Test for File Disclosure
    @Test
    void testFileDisclosure() {
        String payload = "/etc/passwd";
        ResponseEntity<String> response = restTemplate.getForEntity(getBaseUrl() + "/read-file?filename=" + payload, String.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(response.getBody().contains("root")); // Assuming /etc/passwd contains 'root'
    }

    // Test for Command Injection
    @Test
    void testCommandInjection() {
        String payload = "ls";
        ResponseEntity<String> response = restTemplate.getForEntity(getBaseUrl() + "/exec?command=" + payload, String.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    // Test for Sensitive Information Exposure
    @Test
    void testSensitiveInfoExposure() {
        ResponseEntity<String> response = restTemplate.getForEntity(getBaseUrl() + "/debug", String.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(response.getBody().contains("DB_PASSWORD")); // Verify environment or sensitive info is exposed
    }

    // Test for Open Redirect
    @Test
    void testOpenRedirect() {
        String payload = "https://malicious-site.com";
        ResponseEntity<String> response = restTemplate.getForEntity(getBaseUrl() + "/redirect?url=" + payload, String.class);
        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        assertEquals(payload, response.getHeaders().getLocation().toString()); // Verify redirect to user-supplied URL
    }

    // Test for Hardcoded API Key
    @Test
    void testHardcodedApiKey() {
        ResponseEntity<String> response = restTemplate.getForEntity(getBaseUrl() + "/apikey", String.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue(response.getBody().contains("1234567890abcdef")); // Verify hardcoded API key is returned
    }
}
