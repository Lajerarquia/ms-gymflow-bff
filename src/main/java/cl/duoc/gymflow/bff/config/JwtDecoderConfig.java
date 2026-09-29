package cl.duoc.gymflow.bff.config;

import cl.duoc.gymflow.bff.security.AudienceValidator;
import cl.duoc.gymflow.bff.security.TenantValidator;
import cl.duoc.gymflow.bff.security.ValidadorConMensaje;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/**
 * Cómo se valida el JWT que llega desde el API Gateway. Es la misma validación que hace el JWT Authorizer
 * de AWS, repetida en el BFF (defensa en profundidad: si alguien llega al BFF sin pasar por el Gateway,
 * igual se le exige un token válido).
 * <ol>
 *   <li><b>Firma</b>: {@link NimbusJwtDecoder} descarga las llaves públicas de Azure AD desde el JWK Set
 *       (solo cuando llega el primer token, no al arrancar) y verifica la firma. Solo acepta RS256, así que
 *       un token sin firmar ({@code alg: none}) o firmado con HMAC se rechaza.</li>
 *   <li><b>Vigencia</b>: {@code exp} es obligatorio y se revisan {@code exp}/{@code nbf} con 60 s de tolerancia
 *       por diferencias de reloj entre servidores.</li>
 *   <li><b>Issuer</b>: {@code iss} debe ser el de nuestro tenant (tokens v2).</li>
 *   <li><b>Audience</b>: {@code aud} debe ser esta API.</li>
 *   <li><b>Tenant</b>: {@code tid} debe ser nuestro tenant.</li>
 * </ol>
 * Los roles y el scope no se revisan aquí: un token válido sin el rol adecuado es un 403, no un 401.
 */
@Configuration
@EnableConfigurationProperties(SeguridadProperties.class)
public class JwtDecoderConfig {

    static final Duration TOLERANCIA_RELOJ = Duration.ofSeconds(60);

    @Bean
    JwtDecoder jwtDecoder(SeguridadProperties props) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(props.jwkSetUri())
                .jwsAlgorithm(SignatureAlgorithm.RS256)
                .build();
        decoder.setJwtValidator(validadores(props));
        return decoder;
    }

    static OAuth2TokenValidator<Jwt> validadores(SeguridadProperties props) {
        // JwtTimestampValidator deja pasar un token sin "exp"; por eso primero se exige que exista.
        OAuth2TokenValidator<Jwt> expObligatorio = new ValidadorConMensaje(
                new JwtClaimValidator<Instant>("exp", Objects::nonNull),
                jwt -> "El token no tiene fecha de expiración (exp)");

        OAuth2TokenValidator<Jwt> vigencia = new ValidadorConMensaje(
                new JwtTimestampValidator(TOLERANCIA_RELOJ),
                jwt -> jwt.getExpiresAt() != null && jwt.getExpiresAt().isBefore(Instant.now())
                        ? "El token expiró el " + jwt.getExpiresAt()
                        : "El token todavía no es válido (nbf: " + jwt.getNotBefore() + ")");

        OAuth2TokenValidator<Jwt> issuer = new ValidadorConMensaje(
                new JwtIssuerValidator(props.issuer()),
                jwt -> "El emisor del token (" + jwt.getClaimAsString("iss") + ") no es el esperado");

        return new DelegatingOAuth2TokenValidator<>(List.of(
                expObligatorio,
                vigencia,
                issuer,
                new AudienceValidator(props.audiences()),
                new TenantValidator(props.tenantId())));
    }
}
