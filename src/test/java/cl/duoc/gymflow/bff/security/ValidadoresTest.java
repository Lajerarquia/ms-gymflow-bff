package cl.duoc.gymflow.bff.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Pruebas unitarias de cada validador y del conversor de roles, sin levantar Spring.
 */
class ValidadoresTest {

    private static final String CLIENT_ID = "22222222-2222-2222-2222-222222222222";
    private static final String TENANT = "11111111-1111-1111-1111-111111111111";

    private final AudienceValidator audience = new AudienceValidator(List.of(CLIENT_ID, "api://" + CLIENT_ID));
    private final TenantValidator tenant = new TenantValidator(TENANT);

    @Test
    void audience_aceptaTokenV2ConElGuid() {
        assertThat(audience.validate(jwt().audience(List.of(CLIENT_ID)).build()).hasErrors()).isFalse();
    }

    @Test
    void audience_aceptaTokenV1ConApiUri() {
        assertThat(audience.validate(jwt().audience(List.of("api://" + CLIENT_ID)).build()).hasErrors()).isFalse();
    }

    @Test
    void audience_rechazaTokenDeOtraApi() {
        OAuth2TokenValidatorResult resultado = audience.validate(
                jwt().audience(List.of("00000003-0000-0000-c000-000000000000")).build());

        assertThat(resultado.hasErrors()).isTrue();
        assertThat(descripcion(resultado)).contains("no corresponde a esta API");
    }

    @Test
    void audience_rechazaTokenSinAudience() {
        assertThat(audience.validate(jwt().build()).hasErrors()).isTrue();
    }

    @Test
    void tenant_aceptaNuestroTenant() {
        assertThat(tenant.validate(jwt().claim("tid", TENANT).build()).hasErrors()).isFalse();
    }

    @Test
    void tenant_rechazaOtroTenantYTokenSinTid() {
        assertThat(tenant.validate(jwt().claim("tid", "otro").build()).hasErrors()).isTrue();
        assertThat(tenant.validate(jwt().build()).hasErrors()).isTrue();
    }

    @Test
    void rolesConverter_traduceRolesYScopes() {
        Jwt token = jwt()
                .claim("roles", List.of("Admin", "Auditor"))
                .claim("scp", "access_as_user otro.scope")
                .build();

        List<String> authorities = new RolesConverter().convert(token).stream()
                .map(GrantedAuthority::getAuthority).toList();

        assertThat(authorities).containsExactlyInAnyOrder(
                "ROLE_Admin", "ROLE_Auditor", "SCOPE_access_as_user", "SCOPE_otro.scope");
    }

    @Test
    void rolesConverter_tokenSinRolesNiScopes_noDaPermisos() {
        assertThat(new RolesConverter().convert(jwt().build())).isEmpty();
    }

    private static Jwt.Builder jwt() {
        return Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .issuedAt(Instant.now())
                .claim("sub", "usuario");
    }

    private static String descripcion(OAuth2TokenValidatorResult resultado) {
        return resultado.getErrors().stream().map(OAuth2Error::getDescription).findFirst().orElse("");
    }
}
