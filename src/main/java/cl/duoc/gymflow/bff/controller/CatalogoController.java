package cl.duoc.gymflow.bff.controller;

import cl.duoc.gymflow.bff.client.Destino;
import cl.duoc.gymflow.bff.client.DomainClient;
import cl.duoc.gymflow.bff.security.UsuarioActual;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Catálogo: clases ({@code services}) y salas ({@code rooms}). Los permisos por rol están completos en
 * {@code SecurityConfig}, así que aquí solo se reenvía. Las rutas son explícitas (con id numérico)
 * para que el BFF nunca reenvíe a rutas internas del microservicio, como las de tomar o devolver cupo.
 */
@RestController
@RequestMapping("/api/catalog")
public class CatalogoController {

    private static final String CLASES = "/api/catalog/services";
    private static final String SALAS = "/api/catalog/rooms";

    private final DomainClient domainClient;

    public CatalogoController(DomainClient domainClient) {
        this.domainClient = domainClient;
    }

    // ---- Clases ----

    @GetMapping("/services")
    public ResponseEntity<byte[]> listarClases(@RequestParam MultiValueMap<String, String> filtros,
                                               @AuthenticationPrincipal Jwt jwt) {
        return enviar(HttpMethod.GET, CLASES, filtros, null, jwt);
    }

    @GetMapping("/services/{id}")
    public ResponseEntity<byte[]> obtenerClase(@PathVariable Long id, @AuthenticationPrincipal Jwt jwt) {
        return enviar(HttpMethod.GET, CLASES + "/" + id, null, null, jwt);
    }

    @PostMapping("/services")
    public ResponseEntity<byte[]> crearClase(@RequestBody byte[] cuerpo, @AuthenticationPrincipal Jwt jwt) {
        return enviar(HttpMethod.POST, CLASES, null, cuerpo, jwt);
    }

    @PutMapping("/services/{id}")
    public ResponseEntity<byte[]> actualizarClase(@PathVariable Long id, @RequestBody byte[] cuerpo,
                                                  @AuthenticationPrincipal Jwt jwt) {
        return enviar(HttpMethod.PUT, CLASES + "/" + id, null, cuerpo, jwt);
    }

    @DeleteMapping("/services/{id}")
    public ResponseEntity<byte[]> eliminarClase(@PathVariable Long id, @AuthenticationPrincipal Jwt jwt) {
        return enviar(HttpMethod.DELETE, CLASES + "/" + id, null, null, jwt);
    }

    // ---- Salas ----

    @GetMapping("/rooms")
    public ResponseEntity<byte[]> listarSalas(@RequestParam MultiValueMap<String, String> filtros,
                                              @AuthenticationPrincipal Jwt jwt) {
        return enviar(HttpMethod.GET, SALAS, filtros, null, jwt);
    }

    @GetMapping("/rooms/{id}")
    public ResponseEntity<byte[]> obtenerSala(@PathVariable Long id, @AuthenticationPrincipal Jwt jwt) {
        return enviar(HttpMethod.GET, SALAS + "/" + id, null, null, jwt);
    }

    @PostMapping("/rooms")
    public ResponseEntity<byte[]> crearSala(@RequestBody byte[] cuerpo, @AuthenticationPrincipal Jwt jwt) {
        return enviar(HttpMethod.POST, SALAS, null, cuerpo, jwt);
    }

    @PutMapping("/rooms/{id}")
    public ResponseEntity<byte[]> actualizarSala(@PathVariable Long id, @RequestBody byte[] cuerpo,
                                                 @AuthenticationPrincipal Jwt jwt) {
        return enviar(HttpMethod.PUT, SALAS + "/" + id, null, cuerpo, jwt);
    }

    @DeleteMapping("/rooms/{id}")
    public ResponseEntity<byte[]> eliminarSala(@PathVariable Long id, @AuthenticationPrincipal Jwt jwt) {
        return enviar(HttpMethod.DELETE, SALAS + "/" + id, null, null, jwt);
    }

    private ResponseEntity<byte[]> enviar(HttpMethod metodo, String ruta, MultiValueMap<String, String> filtros,
                                          byte[] cuerpo, Jwt jwt) {
        return domainClient.enviar(Destino.CATALOGO, metodo, ruta, filtros, cuerpo, UsuarioActual.desde(jwt));
    }
}
