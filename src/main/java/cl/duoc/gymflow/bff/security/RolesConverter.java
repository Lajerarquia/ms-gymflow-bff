package cl.duoc.gymflow.bff.security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Traduce los claims de Azure AD a authorities de Spring Security:
 * <ul>
 *   <li>{@code roles} (lista, App Roles asignados al usuario) → {@code ROLE_Admin}, {@code ROLE_Socio}, ...</li>
 *   <li>{@code scp} (texto separado por espacios, permisos delegados) → {@code SCOPE_access_as_user}, ...</li>
 * </ul>
 * El convertidor por defecto de Spring solo lee {@code scope}/{@code scp} e ignora {@code roles},
 * por eso hace falta uno propio.
 */
public class RolesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    public static final String PREFIJO_ROL = "ROLE_";
    public static final String PREFIJO_SCOPE = "SCOPE_";

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        List<GrantedAuthority> authorities = new ArrayList<>();

        List<String> roles = jwt.getClaimAsStringList("roles");
        if (roles != null) {
            roles.forEach(rol -> authorities.add(new SimpleGrantedAuthority(PREFIJO_ROL + rol)));
        }

        String scp = jwt.getClaimAsString("scp");
        if (scp != null && !scp.isBlank()) {
            for (String scope : scp.trim().split("\\s+")) {
                authorities.add(new SimpleGrantedAuthority(PREFIJO_SCOPE + scope));
            }
        }
        return authorities;
    }
}
