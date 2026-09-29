package cl.duoc.gymflow.bff.error;

import java.time.Instant;
import org.springframework.http.HttpStatus;

/**
 * Formato único de error del BFF. Lo usan el 401, el 403 y los errores de los controladores,
 * para que el frontend siempre pueda leer {@code message}.
 */
public record ErrorResponse(String timestamp, int status, String error, String message, String path) {

    public static ErrorResponse of(HttpStatus status, String message, String path) {
        return new ErrorResponse(Instant.now().toString(), status.value(), status.getReasonPhrase(), message, path);
    }
}
