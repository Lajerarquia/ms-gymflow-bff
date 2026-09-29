package cl.duoc.gymflow.bff.security;

import java.util.function.Function;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Envuelve un validador estándar de Spring Security para que, si falla, el motivo quede en español
 * y se pueda devolver tal cual en el JSON del 401. La validación en sí la hace el validador original.
 */
public class ValidadorConMensaje implements OAuth2TokenValidator<Jwt> {

    private final OAuth2TokenValidator<Jwt> delegado;
    private final Function<Jwt, String> mensaje;

    public ValidadorConMensaje(OAuth2TokenValidator<Jwt> delegado, Function<Jwt, String> mensaje) {
        this.delegado = delegado;
        this.mensaje = mensaje;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        OAuth2TokenValidatorResult resultado = delegado.validate(jwt);
        if (!resultado.hasErrors()) {
            return resultado;
        }
        return OAuth2TokenValidatorResult.failure(
                new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, mensaje.apply(jwt), null));
    }
}
