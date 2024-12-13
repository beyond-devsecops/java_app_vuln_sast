package com.esure.java_app_vulnerable_sast_demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.io.IOException;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
@RestController
public class VulnerableAppApplication {

    // Hardcoded credentials
    private static final String DB_URL = "jdbc:mysql://localhost:3306/testdb";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "password123"; // Hardcoded and insecure

    public static void main(String[] args) {
        SpringApplication.run(VulnerableAppApplication.class, args);
    }

    // SQL Injection vulnerability
    @GetMapping("/search")
    public ResponseEntity<?> search(@RequestParam String query) throws SQLException {
        Connection connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
        Statement statement = connection.createStatement();
        // Vulnerable to SQL Injection
        String sql = "SELECT * FROM users WHERE username = '" + query + "'";
        ResultSet resultSet = statement.executeQuery(sql);

        Map<String, String> results = new HashMap<>();
        while (resultSet.next()) {
            results.put(resultSet.getString("id"), resultSet.getString("username"));
        }

        connection.close();
        return ResponseEntity.ok(results);
    }

    // Server-Side Request Forgery (SSRF)
    @GetMapping("/fetch")
    public ResponseEntity<?> fetch(@RequestParam String url) throws IOException {
        // SSRF vulnerability
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        connection.setRequestMethod("GET");
        int status = connection.getResponseCode();
        String content = new BufferedReader(new InputStreamReader(connection.getInputStream())).readLine();
        connection.disconnect();

        return ResponseEntity.ok(Map.of("status", status, "content", content));
    }

    // Cross-Site Scripting (XSS)
    @GetMapping("/greet")
    public ResponseEntity<?> greet(@RequestParam(defaultValue = "Guest") String name) {
        // XSS vulnerability
        String htmlResponse = "<h1>Welcome, " + name + "!</h1>";
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE)
                .body(htmlResponse);
    }

    // Insecure Deserialization
    @PostMapping("/deserialize")
    public ResponseEntity<?> deserialize(@RequestBody byte[] data) throws IOException, ClassNotFoundException {
        // Vulnerable deserialization
        ObjectInputStream objectInputStream = new ObjectInputStream(new ByteArrayInputStream(data));
        Object obj = objectInputStream.readObject();
        objectInputStream.close();
        return ResponseEntity.ok("Deserialized object: " + obj.toString());
    }

    // Insecure Cryptography
    @GetMapping("/encrypt")
    public ResponseEntity<?> encrypt(@RequestParam String data) throws Exception {
        String key = "0123456789abcdef"; // Hardcoded key
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // Insecure ECB mode
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedData = cipher.doFinal(data.getBytes());
        String encryptedBase64 = Base64.getEncoder().encodeToString(encryptedData);
        return ResponseEntity.ok("Encrypted data: " + encryptedBase64);
    }

    // File Disclosure
    @GetMapping("/read-file")
    public ResponseEntity<?> readFile(@RequestParam String filename) throws IOException {
        // Arbitrary file read vulnerability
        String content = new String(Files.readAllBytes(Paths.get(filename)));
        return ResponseEntity.ok(content);
    }

    // Command Injection
    @GetMapping("/exec")
    public ResponseEntity<?> exec(@RequestParam String command) throws IOException {
        // Vulnerable command execution
        Process process = Runtime.getRuntime().exec(command);
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String output = reader.readLine();
        reader.close();
        return ResponseEntity.ok("Output: " + output);
    }

    // Expose Sensitive Environment Data
    @GetMapping("/debug")
    public ResponseEntity<?> debug() {
        Map<String, String> env = System.getenv();
        return ResponseEntity.ok(env);
    }

    // Open Redirect
    @GetMapping("/redirect")
    public ResponseEntity<?> redirect(@RequestParam String url) {
        // Open redirect vulnerability
        return ResponseEntity.status(302).header(HttpHeaders.LOCATION, url).build();
    }
}
