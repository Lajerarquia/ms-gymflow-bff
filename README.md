# ms-gymflow-bff

BFF (Backend for Frontend) de GymFlow. Recibe las llamadas del frontend a través de AWS API Gateway,
**vuelve a validar el JWT de Azure AD**, autoriza por rol y reenvía la petición al microservicio de dominio.

```
Angular + MSAL ──Bearer JWT──> API Gateway (JWT Authorizer) ──> ms-gymflow-bff :8080
                                                                 ├─> ms-gymflow-reservations :8081
                                                                 └─> ms-gymflow-catalog :8082
```

## Validación del token (401)

| Qué se valida | Dónde |
|---|---|
| Firma RS256 con las llaves públicas de Azure AD (JWK Set) | `JwtDecoderConfig` (`NimbusJwtDecoder.withJwkSetUri`) |
| `exp` obligatorio, `exp`/`nbf` vigentes (60 s de tolerancia) | `JwtDecoderConfig` |
| `iss` = `https://login.microsoftonline.com/<TENANT_ID>/v2.0` | `JwtDecoderConfig` |
| `aud` = `<CLIENT_ID>` (v2) o `api://<CLIENT_ID>` (v1) | `AudienceValidator` |
| `tid` = `<TENANT_ID>` | `TenantValidator` |

El 401 responde JSON con el motivo real (`"El token expiró el ..."`, `"La firma del token no es válida"`, etc.).

## Autorización (403)

Toda ruta de la API exige el scope `access_as_user` **y** uno de los roles permitidos. Lo no declarado se deniega.

| Endpoint | Admin | Instructor | Socio | Auditor |
|---|:-:|:-:|:-:|:-:|
| `GET /api/me` | ✔ | ✔ | ✔ | ✔ |
| `GET /api/reservations[/{id}]` | ✔ | ✔ | solo las suyas | ✔ |
| `POST /api/reservations` | ✔ | ✔ | solo a su nombre | ✘ |
| `PUT /api/reservations/{id}/status` | ✔ | ✔ | solo CANCELADA y solo las suyas | ✘ |
| `GET /api/catalog/services[/{id}]` | ✔ | ✔ | ✔ | ✔ |
| `POST/PUT/DELETE /api/catalog/services[/{id}]` | ✔ | ✘ | ✘ | ✘ |
| `GET /api/catalog/rooms[/{id}]` | ✔ | ✔ | ✘ | ✘ |
| `POST/PUT/DELETE /api/catalog/rooms[/{id}]` | ✔ | ✘ | ✘ | ✘ |

La identidad viaja a los microservicios en `X-User-Id` (`oid`), `X-User-Name` (URL-encoded UTF-8) y `X-User-Email`.
El access token no se reenvía.

## Ejecutar

```bash
cp .env.example .env         # completar AZURE_TENANT_ID y AZURE_CLIENT_ID
export $(grep -v '^#' .env | xargs)
./mvnw spring-boot:run
```

## Pruebas

```bash
./mvnw test
```

- `FiltroJwtCompletoTest`: tokens RS256 firmados de verdad pasan por la cadena completa de filtros
  (expirado, sin `exp`, audience mala, firma de otra llave, otro tenant, sin firma, sin scope, rol sin permiso).
- `MatrizDeAccesoTest`: la tabla de arriba, endpoint por endpoint y rol por rol.
- `ReservasControllerTest`: reglas del Socio (solo sus reservas, solo CANCELADA).
- `DomainClientTest`: cabeceras `X-User-*`, codificación de filtros y paso de errores del dominio.
- `ValidadoresTest`: audience, tenant y conversión de roles y scopes.
