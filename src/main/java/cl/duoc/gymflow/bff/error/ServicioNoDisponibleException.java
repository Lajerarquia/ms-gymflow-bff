package cl.duoc.gymflow.bff.error;

/**
 * El microservicio de dominio no respondió (caído, sin red o demasiado lento). Se responde 503.
 */
public class ServicioNoDisponibleException extends RuntimeException {

    public ServicioNoDisponibleException(String servicio, Throwable causa) {
        super("El servicio de " + servicio + " no está disponible en este momento", causa);
    }
}
