package cl.duoc.gymflow.bff.support;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;

import cl.duoc.gymflow.bff.security.RolesConverter;
import java.util.List;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.JwtRequestPostProcessor;

/**
 * Usuarios autenticados para pruebas {@code @WebMvcTest}: {@code jwt()} salta la decodificación y la firma
 * (eso se prueba en {@code FiltroJwtCompletoTest}) y deja probar solo la autorización.
 * Los authorities salen del mismo {@link RolesConverter} que usa el BFF.
 */
public final class Usuarios {

    public static final String SCOPE = "access_as_user";

    private Usuarios() {
    }

    public static JwtRequestPostProcessor conRoles(String oid, String... roles) {
        return jwt()
                .jwt(j -> j.claim("oid", oid)
                        .claim("name", "José Pérez")
                        .claim("preferred_username", "jose.perez@gymflow.cl")
                        .claim("scp", SCOPE)
                        .claim("roles", List.of(roles)))
                .authorities(new RolesConverter());
    }

    public static JwtRequestPostProcessor sinScope(String oid, String... roles) {
        return jwt()
                .jwt(j -> j.claim("oid", oid).claim("roles", List.of(roles)))
                .authorities(new RolesConverter());
    }
}
