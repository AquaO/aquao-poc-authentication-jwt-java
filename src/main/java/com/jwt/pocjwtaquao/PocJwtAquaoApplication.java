package com.jwt.pocjwtaquao;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import org.springframework.boot.CommandLineRunner;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jwt.pocjwtaquao.services.PocJwtAquoServices;

@SpringBootApplication
public class PocJwtAquaoApplication implements CommandLineRunner{

	private final RestTemplate restTemplate = new RestTemplate();
	private String sessionId;
	private String principalName;

	@Value("${host}")
	private String host;

	@Value("${session_name}")
	private String sessionName;

	@Autowired
	private PocJwtAquoServices pocJwtAquoServices;

	public static void main(String[] args) {
		SpringApplication.run(PocJwtAquaoApplication.class, args);
	}

	@Override
	public void run(String... args) throws Exception {
		callEndpoint("/api/whoami");
		callEndpoint("/api/security/authentication-support/jwt/logas/" + pocJwtAquoServices.generateJwt());
		callEndpoint("/api/whoami");
		callEndpoint("/api/logout");
	}

	private void callEndpoint(String endpoint) {
		String url = host + endpoint;

		System.out.println("> " + endpoint);

		if (sessionId != null) {
			restTemplate.getInterceptors().add((request, body, execution) -> {
				request.getHeaders().add("Cookie",  sessionName + "=" + sessionId);
				return execution.execute(request, body);
			});
		}

		ResponseEntity<String> response = restTemplate.getForEntity(url, String.class);
		
		if (sessionId == null) {
			sessionId = pocJwtAquoServices.findSessionId(response.getHeaders());
		}

    if (response.getBody() != null) {
        try {
						ObjectMapper objectMapper = new ObjectMapper();
						JsonNode jsonNode = objectMapper.readTree(response.getBody());
            principalName = jsonNode.get("name").asText();
        } catch (Exception e) {
            e.printStackTrace();
        }

				System.out.println("Principal Name: " + principalName);
    }
	}
}

