package cl.duoc.gymflow.bff;

import static cl.duoc.gymflow.bff.support.TokensDePrueba.CLIENT_ID;
import static cl.duoc.gymflow.bff.support.TokensDePrueba.LLAVE_AJENA;
import static cl.duoc.gymflow.bff.support.TokensDePrueba.TENANT;
import static cl.duoc.gymflow.bff.support.TokensDePrueba.claimsValidos;
import static cl.duoc.gymflow.bff.support.TokensDePrueba.firmar;
import static cl.duoc.gymflow.bff.support.TokensDePrueba.sinFirmar;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import cl.duoc.gymflow.bff.support.TokensDePrueba;
import com.sun.net.httpserver.HttpServer;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Prueba de punta a punta de la seguridad: tokens RS256 firmados de verdad pasan por la cadena completa
 * de filtros de Spring Security, con el {@code NimbusJwtDecoder} real descargando las llaves de un JWK Set
 * local. Nada de la validación está simulado.
 */
@SpringBootTest(properties = {
        "AZURE_TENANT_ID=" + TENANT,
        "AZURE_CLIENT_ID=" + CLIENT_ID
})
@AutoConfigureMockMvc
class FiltroJwtCompletoTest {

    private static HttpServer servidorJwks;

    @Autowired
    private MockMvc mvc;

    @DynamicPropertySource
    static void jwkSetLocal(DynamicPropertyRegistry registro) {
        servidorJwks = TokensDePrueba.iniciarServidorJwks();
        registro.add("gymflow.security.jwk-set-uri",
                () -> "http://localhost:" + servidorJwks.getAddress().getPort() + "/keys");
    }

    @AfterAll
    static void detenerJwks() {
        servidorJwks.stop(0);
    }

    @Test
    void tokenValido_responde200_yLeeRolesYScopesDeLosClaims() throws Exception {
        mvc.perform(get("/api/me").header("Authorization", "Bearer " + firmar(claimsValidos("Admin").build())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.oid").value(TokensDePrueba.OID))
                .andExpect(jsonPath("$.nombre").value("José Pérez"))
                .andExpect(jsonPath("$.roles[0]").value("Admin"))
                .andExpect(jsonPath("$.scopes[0]").value("access_as_user"));
    }

    @Test
    void tokenV1ConAudienceApi_seAcepta() throws Exception {
        String token = firmar(claimsValidos("Admin").audience("api://" + CLIENT_ID).build());

        mvc.perform(get("/api/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
    }

    @Test
    void sinToken_responde401() throws Exception {
        mvc.perform(get("/api/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", "Bearer"))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.message", containsString("Falta el token")));
    }

    @Test
    void tokenExpirado_responde401() throws Exception {
        Instant haceDosHoras = Instant.now().minus(Duration.ofHours(2));
        String token = firmar(claimsValidos("Admin")
                .issueTime(Date.from(haceDosHoras))
                .notBeforeTime(Date.from(haceDosHoras))
                .expirationTime(Date.from(Instant.now().minus(Duration.ofMinutes(5))))
                .build());

        mvc.perform(get("/api/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", containsString("invalid_token")))
                .andExpect(jsonPath("$.message", containsString("El token expiró")));
    }

    @Test
    void tokenSinExpiracion_responde401() throws Exception {
        String token = firmar(claimsValidos("Admin").expirationTime(null).build());

        mvc.perform(get("/api/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message", containsString("no tiene fecha de expiración")));
    }

    @Test
    void audienceDeOtraAplicacion_responde401() throws Exception {
        String token = firmar(claimsValidos("Admin").audience("api://otra-aplicacion").build());

        mvc.perform(get("/api/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message", containsString("audience")));
    }

    @Test
    void firmadoConOtraLlave_responde401() throws Exception {
        String token = firmar(claimsValidos("Admin").build(), LLAVE_AJENA);

        mvc.perform(get("/api/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("La firma del token no es válida"));
    }

    @Test
    void issuerYTenantDeOtroDirectorio_responde401() throws Exception {
        String otroTenant = "99999999-9999-9999-9999-999999999999";
        String token = firmar(claimsValidos("Admin")
                .issuer("https://login.microsoftonline.com/" + otroTenant + "/v2.0")
                .claim("tid", otroTenant)
                .build());

        mvc.perform(get("/api/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message", containsString("emisor")))
                .andExpect(jsonPath("$.message", containsString("otro tenant")));
    }

    @Test
    void tokenSinFirma_responde401() throws Exception {
        String token = sinFirmar(claimsValidos("Admin").build());

        mvc.perform(get("/api/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message", containsString("RS256")));
    }

    @Test
    void textoQueNoEsJwt_responde401() throws Exception {
        mvc.perform(get("/api/me").header("Authorization", "Bearer esto-no-es-un-jwt"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message", containsString("formato JWT")));
    }

    @Test
    void tokenValidoSinScope_responde403() throws Exception {
        String token = firmar(claimsValidos("Admin").claim("scp", null).build());

        mvc.perform(get("/api/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.status").value(403))
                .andExpect(jsonPath("$.message", containsString("scope requerido 'access_as_user'")));
    }

    @Test
    void rolSinPermiso_responde403_sinLlegarAlMicroservicio() throws Exception {
        String token = firmar(claimsValidos("Socio").build());

        mvc.perform(post("/api/catalog/services")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"Spinning\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message", containsString("El rol [Socio] no tiene permiso")));
    }
}
