package cl.duoc.gymflow.bff.config;

import cl.duoc.gymflow.bff.client.DomainClient;
import java.net.http.HttpClient;
import java.time.Duration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

/**
 * Cliente HTTP hacia los microservicios de dominio, con tiempos máximos explícitos:
 * si un microservicio se cuelga, el BFF responde 503 en vez de dejar al frontend esperando.
 */
@Configuration
@EnableConfigurationProperties(ServiciosProperties.class)
public class ClientesConfig {

    static final Duration TIEMPO_CONEXION = Duration.ofSeconds(3);
    static final Duration TIEMPO_RESPUESTA = Duration.ofSeconds(10);

    @Bean
    DomainClient domainClient(RestClient.Builder builder, ServiciosProperties servicios) {
        HttpClient httpClient = HttpClient.newBuilder().connectTimeout(TIEMPO_CONEXION).build();
        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(httpClient);
        factory.setReadTimeout(TIEMPO_RESPUESTA);
        RestClient restClient = builder.requestFactory(factory).build();
        return new DomainClient(restClient, servicios.reservationsUrl(), servicios.catalogUrl());
    }
}
