package cl.duoc.gymflow.bff.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import cl.duoc.gymflow.bff.error.ServicioNoDisponibleException;
import cl.duoc.gymflow.bff.security.UsuarioActual;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

/**
 * Revisa lo que el BFF envía de verdad por HTTP al microservicio de dominio (un servidor local simulado).
 */
class DomainClientTest {

    private static final UsuarioActual USUARIO =
            new UsuarioActual("oid-123", "José Pérez", "jose.perez@gymflow.cl", Set.of("Socio"));

    private HttpServer servidor;
    private final AtomicReference<Headers> cabecerasRecibidas = new AtomicReference<>();
    private final AtomicReference<String> rutaRecibida = new AtomicReference<>();
    private final AtomicReference<String> cuerpoRecibido = new AtomicReference<>();
    private DomainClient cliente;

    @BeforeEach
    void levantarMicroservicioSimulado() throws IOException {
        servidor = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        servidor.createContext("/", intercambio -> {
            cabecerasRecibidas.set(intercambio.getRequestHeaders());
            rutaRecibida.set(intercambio.getRequestURI().getRawPath() + "?" + intercambio.getRequestURI().getRawQuery());
            cuerpoRecibido.set(new String(intercambio.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] respuesta = "{\"message\":\"No se puede pasar a EN_CLASE sin CONFIRMAR\"}"
                    .getBytes(StandardCharsets.UTF_8);
            intercambio.getResponseHeaders().add("Content-Type", "application/json");
            intercambio.sendResponseHeaders(409, respuesta.length);
            try (OutputStream salida = intercambio.getResponseBody()) {
                salida.write(respuesta);
            }
        });
        servidor.start();
        String url = "http://localhost:" + servidor.getAddress().getPort() + "/";
        cliente = new DomainClient(RestClient.create(), url, url);
    }

    @AfterEach
    void detener() {
        servidor.stop(0);
    }

    @Test
    void enviaLaIdentidadEnCabeceras_conElNombreCodificadoEnUtf8() {
        cliente.enviar(Destino.RESERVAS, HttpMethod.GET, "/api/reservations", null, null, USUARIO);

        Headers cabeceras = cabecerasRecibidas.get();
        assertThat(cabeceras.getFirst("X-User-Id")).isEqualTo("oid-123");
        assertThat(cabeceras.getFirst("X-User-Email")).isEqualTo("jose.perez@gymflow.cl");
        assertThat(URLDecoder.decode(cabeceras.getFirst("X-User-Name"), StandardCharsets.UTF_8)).isEqualTo("José Pérez");
    }

    @Test
    void noReenviaElAccessToken() {
        cliente.enviar(Destino.RESERVAS, HttpMethod.GET, "/api/reservations", null, null, USUARIO);

        assertThat(cabecerasRecibidas.get().containsKey("Authorization")).isFalse();
    }

    @Test
    void codificaLosFiltros_sinQueElMasSeConviertaEnEspacio() {
        MultiValueMap<String, String> filtros = new LinkedMultiValueMap<>();
        filtros.add("status", "CONFIRMADA");
        filtros.add("from", "2026-10-01T08:00:00+00:00");

        cliente.enviar(Destino.RESERVAS, HttpMethod.GET, "/api/reservations", filtros, null, USUARIO);

        assertThat(rutaRecibida.get())
                .isEqualTo("/api/reservations?status=CONFIRMADA&from=2026-10-01T08%3A00%3A00%2B00%3A00");
    }

    @Test
    void enviaElCuerpoJson_yDevuelveTalCualElErrorDeNegocio() {
        ResponseEntity<byte[]> respuesta = cliente.enviar(Destino.RESERVAS, HttpMethod.PUT,
                "/api/reservations/7/status", null, "{\"status\":\"EN_CLASE\"}".getBytes(StandardCharsets.UTF_8),
                USUARIO);

        assertThat(cuerpoRecibido.get()).isEqualTo("{\"status\":\"EN_CLASE\"}");
        assertThat(cabecerasRecibidas.get().getFirst("Content-Type")).startsWith(MediaType.APPLICATION_JSON_VALUE);
        assertThat(respuesta.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(respuesta.getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_JSON);
        assertThat(new String(respuesta.getBody(), StandardCharsets.UTF_8))
                .contains("No se puede pasar a EN_CLASE sin CONFIRMAR");
    }

    @Test
    void siElMicroservicioNoResponde_lanzaServicioNoDisponible() {
        int puerto = servidor.getAddress().getPort();
        servidor.stop(0);
        DomainClient sinServidor = new DomainClient(RestClient.create(),
                "http://localhost:" + puerto, "http://localhost:" + puerto);

        assertThatThrownBy(() -> sinServidor.enviar(Destino.CATALOGO, HttpMethod.GET, "/api/catalog/services",
                null, null, USUARIO))
                .isInstanceOf(ServicioNoDisponibleException.class)
                .hasMessage("El servicio de catálogo no está disponible en este momento");
    }
}
