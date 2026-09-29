package cl.duoc.gymflow.bff.client;

import cl.duoc.gymflow.bff.error.ServicioNoDisponibleException;
import cl.duoc.gymflow.bff.security.UsuarioActual;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.StringJoiner;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * Reenvía peticiones ya autorizadas a los microservicios de dominio.
 * <ul>
 *   <li>Pasa la identidad en {@code X-User-Id}, {@code X-User-Name} y {@code X-User-Email}.
 *       El nombre va codificado en UTF-8 (URL-encoding) porque las cabeceras HTTP no admiten tildes con
 *       seguridad; el microservicio lo decodifica.</li>
 *   <li>No reenvía el access token: los microservicios de dominio no están expuestos a internet y
 *       confían en el BFF, así el token no viaja más allá de lo necesario.</li>
 *   <li>Devuelve tal cual el código y el cuerpo del microservicio (404, 409, 400...), para que el
 *       frontend reciba el mensaje de negocio original.</li>
 * </ul>
 */
public class DomainClient {

    public static final String CABECERA_ID = "X-User-Id";
    public static final String CABECERA_NOMBRE = "X-User-Name";
    public static final String CABECERA_EMAIL = "X-User-Email";

    private final RestClient restClient;
    private final String urlReservas;
    private final String urlCatalogo;

    public DomainClient(RestClient restClient, String urlReservas, String urlCatalogo) {
        this.restClient = restClient;
        this.urlReservas = quitarBarraFinal(urlReservas);
        this.urlCatalogo = quitarBarraFinal(urlCatalogo);
    }

    public ResponseEntity<byte[]> enviar(Destino destino, HttpMethod metodo, String ruta,
                                         MultiValueMap<String, String> filtros, byte[] cuerpo,
                                         UsuarioActual usuario) {
        String base = destino == Destino.RESERVAS ? urlReservas : urlCatalogo;
        try {
            // Se pasa un URI ya armado: con uri(String) RestClient lo trataría como plantilla y
            // volvería a codificar los "%" del query string.
            RestClient.RequestBodySpec peticion = restClient.method(metodo)
                    .uri(URI.create(base + ruta + query(filtros)))
                    .accept(MediaType.APPLICATION_JSON)
                    .headers(h -> agregarIdentidad(h, usuario));
            if (cuerpo != null) {
                peticion.contentType(MediaType.APPLICATION_JSON).body(cuerpo);
            }
            return peticion.exchange((req, res) -> {
                HttpHeaders cabeceras = new HttpHeaders();
                if (res.getHeaders().getContentType() != null) {
                    cabeceras.setContentType(res.getHeaders().getContentType());
                }
                return new ResponseEntity<>(res.getBody().readAllBytes(), cabeceras, res.getStatusCode());
            });
        } catch (RestClientException e) {
            throw new ServicioNoDisponibleException(destino.nombre(), e);
        }
    }

    private static void agregarIdentidad(HttpHeaders h, UsuarioActual usuario) {
        h.set(CABECERA_ID, usuario.id());
        h.set(CABECERA_NOMBRE, codificar(usuario.nombre()));
        if (usuario.email() != null) {
            h.set(CABECERA_EMAIL, usuario.email());
        }
    }

    /**
     * Arma el query string codificando cada valor. Se hace a mano para que caracteres como "+"
     * (por ejemplo en una fecha con zona horaria) no se interpreten como espacio en el destino.
     */
    static String query(MultiValueMap<String, String> filtros) {
        if (filtros == null || filtros.isEmpty()) {
            return "";
        }
        StringJoiner partes = new StringJoiner("&", "?", "");
        filtros.forEach((nombre, valores) -> valores.forEach(valor ->
                partes.add(codificar(nombre) + "=" + codificar(valor))));
        return partes.toString();
    }

    private static String codificar(String valor) {
        return URLEncoder.encode(valor == null ? "" : valor, StandardCharsets.UTF_8);
    }

    private static String quitarBarraFinal(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
