package cl.duoc.gymflow.bff.client;

/** Microservicios de dominio a los que el BFF reenvía las peticiones. */
public enum Destino {

    RESERVAS("reservas"),
    CATALOGO("catálogo");

    private final String nombre;

    Destino(String nombre) {
        this.nombre = nombre;
    }

    public String nombre() {
        return nombre;
    }
}
