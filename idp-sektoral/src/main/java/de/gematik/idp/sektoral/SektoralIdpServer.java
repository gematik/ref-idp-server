package de.gematik.idp.sektoral;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@RequiredArgsConstructor
public class SektoralIdpServer {

    @SuppressWarnings("java:S4823")
    public static void main(final String[] args) {
        SpringApplication.run(SektoralIdpServer.class, args);
    }
}
