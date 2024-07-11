package jwt_token.authorization.exception_handler.forbidden;

public class ForbiddenException extends RuntimeException {
    public ForbiddenException(String message) {
                super(message);
    }
}
