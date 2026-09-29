package cl.duoc.gymflow.bff.controller;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Devuelve lo que el BFF entendió del token ya validado. Sirve para la demo y para depurar:
 * muestra que el backend lee roles y scopes de los claims, igual que el frontend.
 * Solo exige el scope (no un rol), para que un usuario sin roles asignados también pueda verlo.
 */
@RestController
public class MeController {

    @GetMapping("/api/me")
    public Map<String, Object> me(@AuthenticationPrincipal Jwt jwt) {
        Map<String, Object> datos = new LinkedHashMap<>();
        datos.put("oid", jwt.getClaimAsString("oid"));
        datos.put("nombre", jwt.getClaimAsString("name"));
        datos.put("email", jwt.getClaimAsString("preferred_username"));
        datos.put("roles", valorOListaVacia(jwt.getClaimAsStringList("roles")));
        datos.put("scopes", jwt.getClaimAsString("scp") == null ? List.of()
                : List.of(jwt.getClaimAsString("scp").trim().split("\\s+")));
        datos.put("tenant", jwt.getClaimAsString("tid"));
        datos.put("emisor", jwt.getClaimAsString("iss"));
        datos.put("audiencia", jwt.getAudience());
        datos.put("expira", jwt.getExpiresAt());
        return datos;
    }

    private static List<String> valorOListaVacia(List<String> lista) {
        return lista == null ? List.of() : lista;
    }
}
