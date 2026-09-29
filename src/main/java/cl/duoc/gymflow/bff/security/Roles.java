package cl.duoc.gymflow.bff.security;

/**
 * App Roles definidos en el App Registration "GymFlow" de Azure AD (claim {@code roles} del token).
 */
public final class Roles {

    public static final String ADMIN = "Admin";
    /** Operador del dominio: confirma reservas, registra el ingreso y cierra la clase. */
    public static final String INSTRUCTOR = "Instructor";
    /** Cliente del dominio: reserva y sigue sus clases. */
    public static final String SOCIO = "Socio";
    /** Solo lectura: consulta el timeline de auditoría. */
    public static final String AUDITOR = "Auditor";

    private Roles() {
    }
}
