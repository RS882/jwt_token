package jwt_token.authorization.exception_handler.forbidden;

public class LimitOfLoginsException extends ForbiddenException {

    public LimitOfLoginsException(String userId) {
        super(String.format("User %s has limit of logins.", userId));
    }
}
