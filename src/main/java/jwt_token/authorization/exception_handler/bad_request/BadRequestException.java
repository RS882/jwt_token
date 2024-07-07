package jwt_token.authorization.exception_handler.bad_request;

public class BadRequestException extends RuntimeException {
    public BadRequestException(String message) {
        super(message);
    }
}
