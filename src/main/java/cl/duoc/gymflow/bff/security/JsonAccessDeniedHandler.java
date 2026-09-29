package cl.duoc.gymflow.bff.security;

import cl.duoc.gymflow.bff.error.ErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;

/**
 * Responde 403 en JSON: el token es válido (sabemos quién es), pero no le alcanza para este endpoint.
 * Distingue si falta el scope delegado o si el rol no tiene permiso, para que el motivo quede claro.
 */
public class JsonAccessDeniedHandler implements AccessDeniedHandler {

    private final ObjectMapper objectMapper;
    private final String scopeRequerido;

    public JsonAccessDeniedHandler(ObjectMapper objectMapper, String scopeRequerido) {
        this.objectMapper = objectMapper;
        this.scopeRequerido = scopeRequerido;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        List<String> authorities = auth == null ? List.of()
                : auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();

        String mensaje;
        if (!authorities.contains(RolesConverter.PREFIJO_SCOPE + scopeRequerido)) {
            mensaje = "El token no incluye el scope requerido '" + scopeRequerido + "'";
        } else {
            List<String> roles = authorities.stream()
                    .filter(a -> a.startsWith(RolesConverter.PREFIJO_ROL))
                    .map(a -> a.substring(RolesConverter.PREFIJO_ROL.length()))
                    .toList();
            mensaje = (roles.isEmpty() ? "El usuario no tiene roles asignados" : "El rol " + roles + " no tiene permiso")
                    + " para " + request.getMethod() + " " + request.getRequestURI();
        }

        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        objectMapper.writeValue(response.getOutputStream(),
                ErrorResponse.of(HttpStatus.FORBIDDEN, mensaje, request.getRequestURI()));
    }
}
