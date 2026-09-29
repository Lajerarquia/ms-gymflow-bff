package cl.duoc.gymflow.bff.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import cl.duoc.gymflow.bff.client.Destino;
import cl.duoc.gymflow.bff.client.DomainClient;
import cl.duoc.gymflow.bff.config.SecurityConfig;
import cl.duoc.gymflow.bff.error.ServicioNoDisponibleException;
import cl.duoc.gymflow.bff.security.UsuarioActual;
import cl.duoc.gymflow.bff.support.TokensDePrueba;
import cl.duoc.gymflow.bff.support.Usuarios;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.MultiValueMap;

/**
 * Reglas de reservas que dependen de los datos: un Socio solo ve, crea y cancela sus propias reservas.
 */
@WebMvcTest(controllers = ReservasController.class,
        properties = {
                "AZURE_TENANT_ID=" + TokensDePrueba.TENANT,
                "AZURE_CLIENT_ID=" + TokensDePrueba.CLIENT_ID
        })
@Import(SecurityConfig.class)
class ReservasControllerTest {

    private static final String SOCIO = "oid-socio";
    private static final String OTRO_SOCIO = "oid-otro-socio";

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @MockitoBean
    private DomainClient domainClient;

    @SuppressWarnings("unchecked")
    private final ArgumentCaptor<MultiValueMap<String, String>> filtros = ArgumentCaptor.forClass(MultiValueMap.class);

    @Test
    void socioQueFiltraPorOtroSocio_soloRecibeLasSuyas() throws Exception {
        when(domainClient.enviar(any(), any(), any(), any(), any(), any())).thenReturn(ok("[]"));

        mvc.perform(get("/api/reservations").param("memberId", OTRO_SOCIO).param("status", "CONFIRMADA")
                        .with(Usuarios.conRoles(SOCIO, "Socio")))
                .andExpect(status().isOk());

        verify(domainClient).enviar(eq(Destino.RESERVAS), eq(HttpMethod.GET), eq("/api/reservations"),
                filtros.capture(), isNull(), any());
        assertThat(filtros.getValue().get("memberId")).containsExactly(SOCIO);
        assertThat(filtros.getValue().get("status")).containsExactly("CONFIRMADA");
    }

    @Test
    void instructor_puedeFiltrarPorCualquierSocio() throws Exception {
        when(domainClient.enviar(any(), any(), any(), any(), any(), any())).thenReturn(ok("[]"));

        mvc.perform(get("/api/reservations").param("memberId", OTRO_SOCIO)
                        .with(Usuarios.conRoles("oid-instructor", "Instructor")))
                .andExpect(status().isOk());

        verify(domainClient).enviar(any(), any(), any(), filtros.capture(), any(), any());
        assertThat(filtros.getValue().get("memberId")).containsExactly(OTRO_SOCIO);
    }

    @Test
    void socio_noPuedeVerLaReservaDeOtroSocio() throws Exception {
        when(domainClient.enviar(any(), eq(HttpMethod.GET), eq("/api/reservations/7"), any(), any(), any()))
                .thenReturn(ok(reserva(OTRO_SOCIO)));

        mvc.perform(get("/api/reservations/7").with(Usuarios.conRoles(SOCIO, "Socio")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message").value("No puedes ver la reserva de otro socio"));
    }

    @Test
    void socioQueCreaReserva_quedaASuNombreAunqueMandeOtroSocio() throws Exception {
        when(domainClient.enviar(any(), any(), any(), any(), any(), any()))
                .thenReturn(ResponseEntity.status(HttpStatus.CREATED).body(new byte[0]));
        ArgumentCaptor<byte[]> cuerpo = ArgumentCaptor.forClass(byte[].class);

        mvc.perform(post("/api/reservations").with(Usuarios.conRoles(SOCIO, "Socio"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"classId\":3,\"memberId\":\"" + OTRO_SOCIO + "\",\"memberName\":\"Otro\"}"))
                .andExpect(status().isCreated());

        verify(domainClient).enviar(eq(Destino.RESERVAS), eq(HttpMethod.POST), eq("/api/reservations"),
                isNull(), cuerpo.capture(), any());
        JsonNode enviado = objectMapper.readTree(cuerpo.getValue());
        assertThat(enviado.path("memberId").asText()).isEqualTo(SOCIO);
        assertThat(enviado.path("memberName").asText()).isEqualTo("José Pérez");
        assertThat(enviado.path("classId").asInt()).isEqualTo(3);
    }

    @Test
    void socio_noPuedeConfirmar_niSiquieraSuPropiaReserva() throws Exception {
        mvc.perform(put("/api/reservations/7/status").with(Usuarios.conRoles(SOCIO, "Socio"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"status\":\"CONFIRMADA\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message").value("Un socio solo puede cambiar su reserva a CANCELADA"));

        verifyNoInteractions(domainClient);
    }

    @Test
    void socio_noPuedeCancelarLaReservaDeOtroSocio() throws Exception {
        when(domainClient.enviar(any(), eq(HttpMethod.GET), eq("/api/reservations/7"), any(), any(), any()))
                .thenReturn(ok(reserva(OTRO_SOCIO)));

        mvc.perform(put("/api/reservations/7/status").with(Usuarios.conRoles(SOCIO, "Socio"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"status\":\"CANCELADA\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message").value("No puedes cancelar la reserva de otro socio"));

        verify(domainClient, never()).enviar(any(), eq(HttpMethod.PUT), any(), any(), any(), any());
    }

    @Test
    void socio_cancelaSuPropiaReserva() throws Exception {
        when(domainClient.enviar(any(), eq(HttpMethod.GET), eq("/api/reservations/7"), any(), any(), any()))
                .thenReturn(ok(reserva(SOCIO)));
        when(domainClient.enviar(any(), eq(HttpMethod.PUT), eq("/api/reservations/7/status"), any(), any(), any()))
                .thenReturn(ok("{\"id\":7,\"status\":\"CANCELADA\"}"));

        mvc.perform(put("/api/reservations/7/status").with(Usuarios.conRoles(SOCIO, "Socio"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"status\":\"CANCELADA\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("CANCELADA"));
    }

    @Test
    void socioQueCancelaReservaInexistente_recibeEl404DelMicroservicio() throws Exception {
        when(domainClient.enviar(any(), eq(HttpMethod.GET), eq("/api/reservations/99"), any(), any(), any()))
                .thenReturn(ResponseEntity.status(HttpStatus.NOT_FOUND).contentType(MediaType.APPLICATION_JSON)
                        .body("{\"message\":\"La reserva 99 no existe\"}".getBytes(StandardCharsets.UTF_8)));

        mvc.perform(put("/api/reservations/99/status").with(Usuarios.conRoles(SOCIO, "Socio"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"status\":\"CANCELADA\"}"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.message").value("La reserva 99 no existe"));
    }

    @Test
    void instructor_cambiaEstadoSinRevisarDuenio_yRecibeEl409DelDominio() throws Exception {
        when(domainClient.enviar(any(), eq(HttpMethod.PUT), eq("/api/reservations/7/status"), any(), any(), any()))
                .thenReturn(ResponseEntity.status(HttpStatus.CONFLICT).contentType(MediaType.APPLICATION_JSON)
                        .body("{\"message\":\"No se puede pasar a EN_CLASE sin CONFIRMAR\"}"
                                .getBytes(StandardCharsets.UTF_8)));

        mvc.perform(put("/api/reservations/7/status").with(Usuarios.conRoles("oid-instructor", "Instructor"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"status\":\"EN_CLASE\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("No se puede pasar a EN_CLASE sin CONFIRMAR"));

        verify(domainClient, never()).enviar(any(), eq(HttpMethod.GET), any(), any(), any(), any());
    }

    @Test
    void laIdentidadQueSeEnviaSaleDelToken() throws Exception {
        when(domainClient.enviar(any(), any(), any(), any(), any(), any())).thenReturn(ok("[]"));
        ArgumentCaptor<UsuarioActual> usuario = ArgumentCaptor.forClass(UsuarioActual.class);

        mvc.perform(get("/api/reservations").with(Usuarios.conRoles("oid-admin", "Admin", "Auditor")))
                .andExpect(status().isOk());

        verify(domainClient).enviar(any(), any(), any(), any(), any(), usuario.capture());
        assertThat(usuario.getValue().id()).isEqualTo("oid-admin");
        assertThat(usuario.getValue().nombre()).isEqualTo("José Pérez");
        assertThat(usuario.getValue().email()).isEqualTo("jose.perez@gymflow.cl");
        assertThat(usuario.getValue().roles()).containsExactlyInAnyOrderElementsOf(List.of("Admin", "Auditor"));
    }

    @Test
    void microservicioCaido_responde503() throws Exception {
        when(domainClient.enviar(any(), any(), any(), any(), any(), any()))
                .thenThrow(new ServicioNoDisponibleException("reservas", new RuntimeException("Connection refused")));

        mvc.perform(get("/api/reservations").with(Usuarios.conRoles("oid-admin", "Admin")))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.message").value("El servicio de reservas no está disponible en este momento"));
    }

    @Test
    void cuerpoQueNoEsJson_responde400() throws Exception {
        mvc.perform(post("/api/reservations").with(Usuarios.conRoles("oid-admin", "Admin"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("esto no es json"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("El cuerpo de la petición no es un JSON válido"));
    }

    private static ResponseEntity<byte[]> ok(String json) {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(json.getBytes(StandardCharsets.UTF_8));
    }

    private static String reserva(String memberId) {
        return "{\"id\":7,\"memberId\":\"" + memberId + "\",\"status\":\"CONFIRMADA\"}";
    }
}
