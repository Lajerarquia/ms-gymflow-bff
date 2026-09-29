package cl.duoc.gymflow.bff.error;

/**
 * El rol puede llegar a la ruta, pero no puede hacer esta operación en particular
 * (por ejemplo, un Socio que intenta confirmar una reserva o ver la de otro socio). Se responde 403.
 */
public class OperacionNoPermitidaException extends RuntimeException {

    public OperacionNoPermitidaException(String mensaje) {
        super(mensaje);
    }
}
