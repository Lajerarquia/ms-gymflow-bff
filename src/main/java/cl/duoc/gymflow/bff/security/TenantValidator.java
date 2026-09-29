package cl.duoc.gymflow.bff.security;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Verifica que el token pertenece a nuestro tenant de Azure AD (claim {@code tid}).
 * Es una segunda barrera junto al issuer: aunque las llaves de firma de Microsoft son compartidas
 * entre tenants, un token de otro directorio trae otro {@code tid} y se rechaza.
 */
public class TenantValidator implements OAuth2TokenValidator<Jwt> {

    private final String tenantId;

    public TenantValidator(String tenantId) {
        this.tenantId = tenantId;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        String tid = jwt.getClaimAsString("tid");
        if (tenantId.equalsIgnoreCase(tid)) {
            return OAuth2TokenValidatorResult.success();
        }
        return OAuth2TokenValidatorResult.failure(new OAuth2Error(
                OAuth2ErrorCodes.INVALID_TOKEN,
                "El token pertenece a otro tenant (tid: " + tid + ")",
                null));
    }
}
