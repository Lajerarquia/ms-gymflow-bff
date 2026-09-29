package cl.duoc.gymflow.bff.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import cl.duoc.gymflow.bff.client.DomainClient;
import cl.duoc.gymflow.bff.config.SecurityConfig;
import cl.duoc.gymflow.bff.support.TokensDePrueba;
import cl.duoc.gymflow.bff.support.Usuarios;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Matriz de autorización del BFF: para cada endpoint, qué responde a cada rol.
 * El microservicio de dominio está simulado y responde 200 con una reserva del propio socio,
 * así que un 403 aquí solo puede venir de la autorización del BFF.
 */
@WebMvcTest(controllers = {ReservasController.class, CatalogoController.class, MeController.class},
        properties = {
                "AZURE_TENANT_ID=" + TokensDePrueba.TENANT,
                "AZURE_CLIENT_ID=" + TokensDePrueba.CLIENT_ID
        })
@Import(SecurityConfig.class)
class MatrizDeAccesoTest {

    private static final String[] ROLES = {"Admin", "Instructor", "Socio", "Auditor"};

    @Autowired
    private MockMvc mvc;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @MockitoBean
    private DomainClient domainClient;

    @BeforeEach
    void microservicioResponde200() {
        when(domainClient.enviar(any(), any(), any(), any(), any(), any())).thenAnswer(inv ->
                ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON)
                        .body("{\"id\":1,\"memberId\":\"oid-Socio\"}".getBytes(StandardCharsets.UTF_8)));
    }

    @ParameterizedTest(name = "{0} {1} → Admin {2}, Instructor {3}, Socio {4}, Auditor {5}")
    @CsvSource({
            "GET,    /api/me,                        200, 200, 200, 200",
            "GET,    /api/reservations,              200, 200, 200, 200",
            "GET,    /api/reservations/1,            200, 200, 200, 200",
            "POST,   /api/reservations,              200, 200, 200, 403",
            "PUT,    /api/reservations/1/status,     200, 200, 200, 403",
            "GET,    /api/catalog/services,          200, 200, 200, 200",
            "GET,    /api/catalog/services/1,        200, 200, 200, 200",
            "POST,   /api/catalog/services,          200, 403, 403, 403",
            "PUT,    /api/catalog/services/1,        200, 403, 403, 403",
            "DELETE, /api/catalog/services/1,        200, 403, 403, 403",
            "GET,    /api/catalog/rooms,             200, 200, 403, 403",
            "GET,    /api/catalog/rooms/1,           200, 200, 403, 403",
            "POST,   /api/catalog/rooms,             200, 403, 403, 403",
            "PUT,    /api/catalog/rooms/1,           200, 403, 403, 403",
            "DELETE, /api/catalog/rooms/1,           200, 403, 403, 403",
            "GET,    /api/ruta-no-declarada,         403, 403, 403, 403"
    })
    void matriz(String metodo, String ruta, int admin, int instructor, int socio, int auditor) throws Exception {
        int[] esperados = {admin, instructor, socio, auditor};
        for (int i = 0; i < ROLES.length; i++) {
            String rol = ROLES[i];
            int obtenido = mvc.perform(request(HttpMethod.valueOf(metodo), ruta)
                            .with(Usuarios.conRoles("oid-" + rol, rol))
                            .contentType(MediaType.APPLICATION_JSON)
                            // CANCELADA sobre una reserva propia: lo único que un Socio puede hacer en /status
                            .content("{\"status\":\"CANCELADA\",\"classId\":1}"))
                    .andReturn().getResponse().getStatus();
            assertThat(obtenido).as("%s %s con rol %s", metodo, ruta, rol).isEqualTo(esperados[i]);
        }
    }

    @Test
    void sinToken_responde401() throws Exception {
        mvc.perform(get("/api/reservations"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").exists());
    }

    @Test
    void conRolPeroSinScope_responde403() throws Exception {
        mvc.perform(get("/api/reservations").with(Usuarios.sinScope("oid-Admin", "Admin")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message").value("El token no incluye el scope requerido 'access_as_user'"));
    }

    @Test
    void conScopePeroSinRoles_puedeVerMe_peroNoLaApi() throws Exception {
        mvc.perform(get("/api/me").with(Usuarios.conRoles("oid-nuevo")))
                .andExpect(status().isOk());
        mvc.perform(get("/api/reservations").with(Usuarios.conRoles("oid-nuevo")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message").value("El usuario no tiene roles asignados para GET /api/reservations"));
    }
}
