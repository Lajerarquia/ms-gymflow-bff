package cl.duoc.gymflow.bff.security;

import java.util.List;
import java.util.Set;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Identidad del usuario sacada del token ya validado. Es lo que el BFF envía a los microservicios
 * de dominio en las cabeceras {@code X-User-*}.
 *
 * @param id     claim {@code oid}: identificador del usuario, estable dentro del tenant
 *               ({@code sub} cambia según la aplicación, por eso no se usa)
 * @param nombre claim {@code name}
 * @param email  claim {@code preferred_username} (en Azure AD suele ser el correo)
 * @param roles  claim {@code roles}
 */
public record UsuarioActual(String id, String nombre, String email, Set<String> roles) {

    public static UsuarioActual desde(Jwt jwt) {
        String id = primeroNoVacio(jwt.getClaimAsString("oid"), jwt.getSubject());
        String email = primeroNoVacio(jwt.getClaimAsString("preferred_username"),
                jwt.getClaimAsString("email"), jwt.getClaimAsString("upn"));
        String nombre = primeroNoVacio(jwt.getClaimAsString("name"), email, id);
        List<String> roles = jwt.getClaimAsStringList("roles");
        return new UsuarioActual(id, nombre, email, roles == null ? Set.of() : Set.copyOf(roles));
    }

    public boolean tieneRol(String rol) {
        return roles.contains(rol);
    }

    /** Admin, Instructor y Auditor ven todas las reservas; un Socio solo las suyas. */
    public boolean puedeVerTodasLasReservas() {
        return tieneRol(Roles.ADMIN) || tieneRol(Roles.INSTRUCTOR) || tieneRol(Roles.AUDITOR);
    }

    /** Admin e Instructor gestionan reservas de cualquier socio; un Socio solo las suyas. */
    public boolean gestionaTodasLasReservas() {
        return tieneRol(Roles.ADMIN) || tieneRol(Roles.INSTRUCTOR);
    }

    private static String primeroNoVacio(String... valores) {
        for (String valor : valores) {
            if (valor != null && !valor.isBlank()) {
                return valor;
            }
        }
        return null;
    }
}
