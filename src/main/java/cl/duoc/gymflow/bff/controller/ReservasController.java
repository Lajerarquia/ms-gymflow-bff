package cl.duoc.gymflow.bff.controller;

import cl.duoc.gymflow.bff.client.Destino;
import cl.duoc.gymflow.bff.client.DomainClient;
import cl.duoc.gymflow.bff.error.OperacionNoPermitidaException;
import cl.duoc.gymflow.bff.security.UsuarioActual;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Reservas. {@code SecurityConfig} ya decidió qué roles llegan aquí; este controlador aplica las reglas
 * que dependen de los datos, para el usuario que es solo Socio:
 * <ul>
 *   <li>listar: se fuerza {@code memberId} = su {@code oid}, aunque mande otro filtro;</li>
 *   <li>ver una reserva: 403 si es de otro socio;</li>
 *   <li>crear: la reserva queda a su nombre, aunque el cuerpo diga otro socio;</li>
 *   <li>cambiar estado: solo a CANCELADA y solo sus propias reservas; cualquier otro caso es 403.</li>
 * </ul>
 * Admin e Instructor gestionan las reservas de cualquier socio. El Auditor solo lee.
 */
@RestController
@RequestMapping("/api/reservations")
public class ReservasController {

    static final String RUTA = "/api/reservations";
    static final String ESTADO_CANCELADA = "CANCELADA";

    private final DomainClient domainClient;
    private final ObjectMapper objectMapper;

    public ReservasController(DomainClient domainClient, ObjectMapper objectMapper) {
        this.domainClient = domainClient;
        this.objectMapper = objectMapper;
    }

    /** Filtros: status, memberId, classId, from, to. */
    @GetMapping
    public ResponseEntity<byte[]> listar(@RequestParam MultiValueMap<String, String> filtros,
                                         @AuthenticationPrincipal Jwt jwt) {
        UsuarioActual usuario = UsuarioActual.desde(jwt);
        MultiValueMap<String, String> filtrosFinales = new LinkedMultiValueMap<>(filtros);
        if (!usuario.puedeVerTodasLasReservas()) {
            filtrosFinales.set("memberId", usuario.id());
        }
        return domainClient.enviar(Destino.RESERVAS, HttpMethod.GET, RUTA, filtrosFinales, null, usuario);
    }

    @GetMapping("/{id}")
    public ResponseEntity<byte[]> obtener(@PathVariable Long id, @AuthenticationPrincipal Jwt jwt) {
        UsuarioActual usuario = UsuarioActual.desde(jwt);
        ResponseEntity<byte[]> respuesta = buscar(id, usuario);
        if (!usuario.puedeVerTodasLasReservas() && respuesta.getStatusCode().is2xxSuccessful()) {
            exigirQueSeaDelSocio(respuesta.getBody(), usuario, "No puedes ver la reserva de otro socio");
        }
        return respuesta;
    }

    @PostMapping
    public ResponseEntity<byte[]> crear(@RequestBody ObjectNode cuerpo, @AuthenticationPrincipal Jwt jwt)
            throws JsonProcessingException {
        UsuarioActual usuario = UsuarioActual.desde(jwt);
        if (!usuario.gestionaTodasLasReservas()) {
            cuerpo.put("memberId", usuario.id());
            cuerpo.put("memberName", usuario.nombre());
        }
        return domainClient.enviar(Destino.RESERVAS, HttpMethod.POST, RUTA, null,
                objectMapper.writeValueAsBytes(cuerpo), usuario);
    }

    @PutMapping("/{id}/status")
    public ResponseEntity<byte[]> cambiarEstado(@PathVariable Long id, @RequestBody ObjectNode cuerpo,
                                                @AuthenticationPrincipal Jwt jwt) throws JsonProcessingException {
        UsuarioActual usuario = UsuarioActual.desde(jwt);
        if (!usuario.gestionaTodasLasReservas()) {
            if (!ESTADO_CANCELADA.equals(cuerpo.path("status").asText())) {
                throw new OperacionNoPermitidaException("Un socio solo puede cambiar su reserva a " + ESTADO_CANCELADA);
            }
            ResponseEntity<byte[]> actual = buscar(id, usuario);
            if (!actual.getStatusCode().is2xxSuccessful()) {
                return actual;
            }
            exigirQueSeaDelSocio(actual.getBody(), usuario, "No puedes cancelar la reserva de otro socio");
        }
        return domainClient.enviar(Destino.RESERVAS, HttpMethod.PUT, RUTA + "/" + id + "/status", null,
                objectMapper.writeValueAsBytes(cuerpo), usuario);
    }

    private ResponseEntity<byte[]> buscar(Long id, UsuarioActual usuario) {
        return domainClient.enviar(Destino.RESERVAS, HttpMethod.GET, RUTA + "/" + id, null, null, usuario);
    }

    private void exigirQueSeaDelSocio(byte[] reservaJson, UsuarioActual usuario, String mensaje) {
        String memberId;
        try {
            JsonNode reserva = objectMapper.readTree(reservaJson);
            memberId = reserva.path("memberId").asText(null);
        } catch (IOException e) {
            memberId = null;
        }
        if (memberId == null || !memberId.equals(usuario.id())) {
            throw new OperacionNoPermitidaException(mensaje);
        }
    }
}
