package cl.duoc.gymflow.bff.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Datos del IDaaS (Azure AD) con los que se valida el JWT.
 * Se validan al arrancar: si falta alguno, el BFF no levanta (mejor fallar temprano que aceptar tokens sin revisar).
 *
 * @param tenantId      tenant de Azure AD; se compara con el claim {@code tid}
 * @param issuer        emisor esperado (tokens v2: https://login.microsoftonline.com/&lt;TENANT_ID&gt;/v2.0)
 * @param jwkSetUri     URL con las llaves públicas para verificar la firma
 * @param audiences     audiences aceptadas: el client id (tokens v2) y api://&lt;CLIENT_ID&gt; (tokens v1)
 * @param requiredScope scope delegado que debe traer el token en el claim {@code scp}
 */
@Validated
@ConfigurationProperties(prefix = "gymflow.security")
public record SeguridadProperties(
        @NotBlank String tenantId,
        @NotBlank String issuer,
        @NotBlank String jwkSetUri,
        @NotEmpty List<String> audiences,
        @NotBlank String requiredScope,
        List<String> corsAllowedOrigins) {

    public SeguridadProperties {
        corsAllowedOrigins = corsAllowedOrigins == null ? List.of() : List.copyOf(corsAllowedOrigins);
    }
}
