package cl.duoc.gymflow.bff.security;

import java.util.List;
import java.util.Set;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Verifica que el token fue emitido PARA esta API (claim {@code aud}).
 * <p>
 * Azure AD pone en {@code aud} el client id (GUID) si el token es v2, o {@code api://<CLIENT_ID>} si es v1.
 * Por eso se acepta cualquiera de las audiences configuradas. Un token emitido para otra aplicación
 * (por ejemplo, para Microsoft Graph) tiene otra audience y se rechaza aunque la firma sea válida.
 */
public class AudienceValidator implements OAuth2TokenValidator<Jwt> {

    private final Set<String> audiencesAceptadas;

    public AudienceValidator(List<String> audiencesAceptadas) {
        this.audiencesAceptadas = Set.copyOf(audiencesAceptadas);
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        List<String> audiencesDelToken = jwt.getAudience();
        if (audiencesDelToken != null && audiencesDelToken.stream().anyMatch(audiencesAceptadas::contains)) {
            return OAuth2TokenValidatorResult.success();
        }
        return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                OAuth2ErrorCodes.INVALID_TOKEN,
                "La audience del token (" + audiencesDelToken + ") no corresponde a esta API",
                null));
    }
}
