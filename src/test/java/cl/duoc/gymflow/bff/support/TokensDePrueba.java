package cl.duoc.gymflow.bff.support;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

/**
 * Emite tokens RS256 firmados de verdad, con la misma forma que los access tokens v2 de Azure AD,
 * y publica la llave pública en un JWK Set local (el equivalente de login.microsoftonline.com/.../keys).
 */
public final class TokensDePrueba {

    public static final String TENANT = "11111111-1111-1111-1111-111111111111";
    public static final String CLIENT_ID = "22222222-2222-2222-2222-222222222222";
    public static final String ISSUER = "https://login.microsoftonline.com/" + TENANT + "/v2.0";
    public static final String OID = "oid-usuario";

    /** Llave que "publica" el IDaaS. */
    public static final RSAKey LLAVE_IDAAS = generarLlave("llave-idaas");
    /** Llave de un atacante con el mismo kid: el token parece del IDaaS, pero la firma no calza. */
    public static final RSAKey LLAVE_AJENA = generarLlave("llave-idaas");

    private TokensDePrueba() {
    }

    /** Claims de un token válido para esta API, con el scope y los roles indicados. */
    public static JWTClaimsSet.Builder claimsValidos(String... roles) {
        Instant ahora = Instant.now();
        return new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience(CLIENT_ID)
                .subject("sub-por-aplicacion")
                .claim("tid", TENANT)
                .claim("oid", OID)
                .claim("name", "José Pérez")
                .claim("preferred_username", "jose.perez@gymflow.cl")
                .claim("scp", "access_as_user")
                .claim("roles", List.of(roles))
                .issueTime(Date.from(ahora))
                .notBeforeTime(Date.from(ahora))
                .expirationTime(Date.from(ahora.plus(Duration.ofHours(1))));
    }

    public static String firmar(JWTClaimsSet claims) {
        return firmar(claims, LLAVE_IDAAS);
    }

    public static String firmar(JWTClaimsSet claims, RSAKey llave) {
        try {
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(llave.getKeyID()).build(), claims);
            jwt.sign(new RSASSASigner(llave));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Token con {@code alg: none}: sin firma. */
    public static String sinFirmar(JWTClaimsSet claims) {
        return new PlainJWT(claims).serialize();
    }

    /** Levanta un servidor HTTP local que sirve el JWK Set con la llave pública del IDaaS. */
    public static HttpServer iniciarServidorJwks() {
        try {
            HttpServer servidor = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
            byte[] jwks = new JWKSet(LLAVE_IDAAS.toPublicJWK()).toString().getBytes(StandardCharsets.UTF_8);
            servidor.createContext("/keys", intercambio -> {
                intercambio.getResponseHeaders().add("Content-Type", "application/json");
                intercambio.sendResponseHeaders(200, jwks.length);
                try (OutputStream salida = intercambio.getResponseBody()) {
                    salida.write(jwks);
                }
            });
            servidor.start();
            return servidor;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static RSAKey generarLlave(String kid) {
        try {
            return new RSAKeyGenerator(2048).keyID(kid).generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }
}
