package cl.duoc.gymflow.bff.config;

import static cl.duoc.gymflow.bff.security.Roles.ADMIN;
import static cl.duoc.gymflow.bff.security.Roles.AUDITOR;
import static cl.duoc.gymflow.bff.security.Roles.INSTRUCTOR;
import static cl.duoc.gymflow.bff.security.Roles.SOCIO;
import static org.springframework.http.HttpMethod.DELETE;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.OPTIONS;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpMethod.PUT;

import cl.duoc.gymflow.bff.security.JsonAccessDeniedHandler;
import cl.duoc.gymflow.bff.security.JsonAuthEntryPoint;
import cl.duoc.gymflow.bff.security.RolesConverter;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagers;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Autorización del BFF. Cada ruta de la API exige dos cosas del token ya validado:
 * <ol>
 *   <li>el scope delegado {@code access_as_user} (el usuario consintió que el front llame a esta API), y</li>
 *   <li>uno de los App Roles permitidos para esa ruta.</li>
 * </ol>
 * Sin token o con token inválido → 401. Token válido sin scope o sin el rol → 403.
 * Todo lo que no esté en la matriz se deniega ({@code denyAll}): si mañana se agrega un endpoint
 * y se olvida declararlo aquí, queda cerrado en vez de abierto.
 * <p>
 * Las reglas de "solo sus propias reservas" del Socio dependen del contenido de la reserva, así que
 * se aplican en {@code ReservasController}; aquí solo se decide qué roles pueden llegar a cada ruta.
 */
@Configuration
@EnableWebSecurity
@EnableConfigurationProperties(SeguridadProperties.class)
public class SecurityConfig {

    private final SeguridadProperties props;

    public SecurityConfig(SeguridadProperties props) {
        this.props = props;
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http, ObjectMapper objectMapper) throws Exception {
        JsonAuthEntryPoint entryPoint = new JsonAuthEntryPoint(objectMapper);
        JsonAccessDeniedHandler accessDeniedHandler =
                new JsonAccessDeniedHandler(objectMapper, props.requiredScope());

        http
                // API sin estado: no hay sesión ni cookies, así que CSRF no aplica.
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(OPTIONS, "/**").permitAll()
                        .requestMatchers("/actuator/health", "/actuator/health/**", "/error").permitAll()

                        .requestMatchers(GET, "/api/me").access(soloScope())

                        .requestMatchers(GET, "/api/reservations", "/api/reservations/*")
                                .access(scopeYRol(ADMIN, INSTRUCTOR, SOCIO, AUDITOR))
                        .requestMatchers(POST, "/api/reservations").access(scopeYRol(ADMIN, INSTRUCTOR, SOCIO))
                        .requestMatchers(PUT, "/api/reservations/*/status").access(scopeYRol(ADMIN, INSTRUCTOR, SOCIO))

                        .requestMatchers(GET, "/api/catalog/services", "/api/catalog/services/*")
                                .access(scopeYRol(ADMIN, INSTRUCTOR, SOCIO, AUDITOR))
                        .requestMatchers(POST, "/api/catalog/services").access(scopeYRol(ADMIN))
                        .requestMatchers(PUT, "/api/catalog/services/*").access(scopeYRol(ADMIN))
                        .requestMatchers(DELETE, "/api/catalog/services/*").access(scopeYRol(ADMIN))

                        .requestMatchers(GET, "/api/catalog/rooms", "/api/catalog/rooms/*")
                                .access(scopeYRol(ADMIN, INSTRUCTOR))
                        .requestMatchers(POST, "/api/catalog/rooms").access(scopeYRol(ADMIN))
                        .requestMatchers(PUT, "/api/catalog/rooms/*").access(scopeYRol(ADMIN))
                        .requestMatchers(DELETE, "/api/catalog/rooms/*").access(scopeYRol(ADMIN))

                        .anyRequest().denyAll())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(accessDeniedHandler))
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(accessDeniedHandler));
        return http.build();
    }

    /** Usa {@link RolesConverter} para los authorities y el {@code oid} como identificador del usuario. */
    static JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new RolesConverter());
        converter.setPrincipalClaimName("oid");
        return converter;
    }

    private AuthorizationManager<RequestAuthorizationContext> soloScope() {
        return AuthorityAuthorizationManager.hasAuthority(RolesConverter.PREFIJO_SCOPE + props.requiredScope());
    }

    private AuthorizationManager<RequestAuthorizationContext> scopeYRol(String... roles) {
        return AuthorizationManagers.allOf(soloScope(), AuthorityAuthorizationManager.hasAnyRole(roles));
    }

    /**
     * CORS para desarrollo local (ng serve → BFF directo). En AWS el preflight lo responde el API Gateway.
     * Solo se permiten los orígenes configurados en {@code GYMFLOW_CORS_ORIGINS}.
     */
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration cors = new CorsConfiguration();
        cors.setAllowedOrigins(props.corsAllowedOrigins());
        cors.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        cors.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        cors.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", cors);
        return source;
    }
}
