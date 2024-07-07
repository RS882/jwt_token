package jwt_token.authorization.exception_handler.authentication_exception;

import org.springframework.security.core.AuthenticationException;

public class WrongTokenException extends AuthenticationException{
    public WrongTokenException(String msg) {
        super(msg);
    }
}
