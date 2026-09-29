package cl.duoc.gymflow.bff.config;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * URLs internas de los microservicios de dominio (red privada de Docker, no expuestas a internet).
 */
@Validated
@ConfigurationProperties(prefix = "gymflow.services")
public record ServiciosProperties(
        @NotBlank String reservationsUrl,
        @NotBlank String catalogUrl) {
}
