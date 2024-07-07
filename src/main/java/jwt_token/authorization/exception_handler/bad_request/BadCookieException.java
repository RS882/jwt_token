package jwt_token.authorization.exception_handler.bad_request;

public class BadCookieException extends BadRequestException {
    public BadCookieException(String message) {
        super(message);
    }
}
