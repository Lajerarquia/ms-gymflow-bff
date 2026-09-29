package cl.duoc.gymflow.bff.security;

import cl.duoc.gymflow.bff.error.ErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.stream.Collectors;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.web.AuthenticationEntryPoint;

/**
 * Responde 401 en JSON cuando no hay token o el token no es válido.
 * <p>
 * Spring Security solo informa un "Invalid token" genérico. Aquí se recorre la cadena de causas hasta
 * {@link JwtValidationException} (falló un validador: expiración, issuer, audience, tenant) o
 * {@link BadJwtException} (falló la firma o el formato) para devolver el motivo real.
 */
public class JsonAuthEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    public JsonAuthEntryPoint(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        boolean faltaToken = authException instanceof InsufficientAuthenticationException;

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        // RFC 6750: el cliente debe saber que se espera un Bearer token y, si lo envió, que es inválido.
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, faltaToken ? "Bearer" : "Bearer error=\"invalid_token\"");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        objectMapper.writeValue(response.getOutputStream(),
                ErrorResponse.of(HttpStatus.UNAUTHORIZED, motivo(authException), request.getRequestURI()));
    }

    static String motivo(AuthenticationException ex) {
        if (ex instanceof InsufficientAuthenticationException) {
            return "Falta el token: envía la cabecera Authorization: Bearer <access_token>";
        }
        for (Throwable causa = ex; causa != null; causa = causa.getCause()) {
            if (causa instanceof JwtValidationException validacion) {
                return validacion.getErrors().stream()
                        .map(OAuth2Error::getDescription)
                        .collect(Collectors.joining("; "));
            }
            if (causa instanceof BadJwtException malFormado) {
                return motivoDeDecodificacion(malFormado.getMessage());
            }
        }
        return "El token no es válido";
    }

    /** Traduce los mensajes de Nimbus (la librería que decodifica y verifica la firma). */
    private static String motivoDeDecodificacion(String mensaje) {
        String texto = mensaje == null ? "" : mensaje;
        if (texto.contains("Invalid signature")) {
            return "La firma del token no es válida";
        }
        if (texto.contains("no matching key")) {
            return "La firma del token no corresponde a ninguna llave publicada por el IDaaS";
        }
        if (texto.contains("Unsupported algorithm") || texto.contains("Unsecured")) {
            return "El token debe venir firmado con RS256";
        }
        return "El token no tiene un formato JWT válido";
    }
}
