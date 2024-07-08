package jwt_token.authorization.servieses.interfaces;

import jakarta.servlet.http.HttpServletRequest;
import jwt_token.authorization.domain.dto.LoginDto;
import jwt_token.authorization.domain.dto.TokenResponseDto;
import jwt_token.authorization.domain.dto.TokensDto;
import jwt_token.authorization.domain.dto.ValidationResponseDto;
import org.springframework.security.core.Authentication;

public interface AuthService {
    TokensDto login(LoginDto loginDto);
    TokensDto refresh(HttpServletRequest request);
    ValidationResponseDto validation( String authorizationHeader);
    void logout( HttpServletRequest request);
    TokenResponseDto getTokenResponseDto(TokensDto tokensDto);

}
