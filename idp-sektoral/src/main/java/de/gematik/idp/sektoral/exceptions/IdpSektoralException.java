package de.gematik.idp.sektoral.exceptions;

public class IdpSektoralException extends RuntimeException {

    public IdpSektoralException(final Exception e) {
        super(e);
    }

    public IdpSektoralException(final String message, final Exception e) {
        super(message, e);
    }
}
