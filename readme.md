
# Vulnerable Spring Boot Application

This project is an intentionally vulnerable Spring Boot application designed for security testing and learning purposes. It includes various common application security vulnerabilities that can be exploited using tools like OWASP ZAP, Burp Suite, SonarQube, or manual testing.

---

## Features

The application contains the following vulnerabilities:

1. **SQL Injection**: Unvalidated user input in SQL queries.
2. **Server-Side Request Forgery (SSRF)**: Direct use of user-supplied URLs in HTTP requests.
3. **Cross-Site Scripting (XSS)**: Reflected user input in HTML responses without sanitization.
4. **Insecure Deserialization**: Unsafe deserialization of user-provided data.
5. **Insecure Cryptography**: Use of hardcoded encryption keys and insecure cipher modes (ECB).
6. **Hardcoded Secrets**: Database credentials and API keys are hardcoded in the source code.
7. **Command Injection**: Direct execution of user-provided commands.
8. **File Disclosure**: Arbitrary file read vulnerability.
9. **Sensitive Information Exposure**: Exposing environment variables and sensitive configurations.
10. **Open Redirect**: Redirecting users to unvalidated URLs.
11. **Weak Error Handling**: Exposing stack traces and error messages.
12. **Insufficient File Upload Validation**: Accepting uploaded files without proper validation.
13. **Weak Password Storage**: Storing passwords using insecure hashing algorithms (MD5).
14. **Race Conditions**: Unsynchronized updates to shared resources.

---

## Getting Started

### Prerequisites

- **Java Development Kit (JDK)**: Version 11 or later.
- **Maven**: Build tool for Java.
- **MySQL**: A database to simulate SQL Injection.
- **Postman** or similar tools for API testing.

---

### Setting Up the Database

1. Start a MySQL server and create a database:
   ```sql
   CREATE DATABASE testdb;
   USE testdb;
   CREATE TABLE users (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255), password VARCHAR(255));
   INSERT INTO users (username, password) VALUES ('admin', 'admin123');
   ```

### Running the Application

	1.	Clone the repository:

```
git clone https://github.com/your-repo/vulnerable-springboot-app.git
cd vulnerable-springboot-app
```

	2.	Build the project:
```
mvn clean install
```

	3.	Run the application:
```
mvn spring-boot:run
```

	4.	Access the application at:
```
http://localhost:8080
```
### Endpoints and Vulnerabilities

Endpoint	HTTP Method	Description	Vulnerability
/search	GET	Search users by name.	SQL Injection
/fetch	GET	Fetch a user-provided URL.	SSRF
/greet	GET	Greet the user with their name.	Cross-Site Scripting (XSS)
/deserialize	POST	Deserialize user-provided data.	Insecure Deserialization
/encrypt	GET	Encrypt user data.	Insecure Cryptography
/read-file	GET	Read the contents of a file.	File Disclosure
/exec	GET	Execute a user-provided command.	Command Injection
/debug	GET	Show debug information, including environment variables.	Sensitive Information Exposure
/redirect	GET	Redirect to a user-provided URL.	Open Redirect
/register	POST	Register a new user with a weak password hashing mechanism.	Weak Password Storage
/upload	POST	Upload a file without validation.	Insufficient File Upload Validation
/increment	GET	Increment a shared counter (vulnerable to race conditions).	Race Condition
/apikey	GET	Return a hardcoded API key.	Hardcoded Secrets

#### Testing

### Manual Testing

	•	Use tools like Postman or curl to send requests and analyze responses.
	•	Test for vulnerabilities such as SQL Injection, XSS, SSRF, and more.

### Automated Testing

	1.	Run the included JUnit tests:
```
mvn test
```

	2.	Scan the application with security tools like:
	•	OWASP ZAP
	•	Burp Suite
	•	SonarQube

### Example Exploits

	1.	`SQL Injection:`
```
curl "http://localhost:8080/search?query=' OR '1'='1"
```

	2.	`SSRF`:
```
curl "http://localhost:8080/fetch?url=http://example.com"


	3.	`Command Injection:`
```
curl "http://localhost:8080/exec?command=ls"
```

	4.	File Disclosure:
```
curl "http://localhost:8080/read-file?filename=/etc/passwd"
```

