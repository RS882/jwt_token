package jwt_token.authorization.exception_handler.exceptions.not_found;

public class TokenNotFoundException extends NotFoundException {
    public TokenNotFoundException(String message) {
        super(message);
    }
}
