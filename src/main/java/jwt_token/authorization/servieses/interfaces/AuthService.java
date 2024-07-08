package jwt_token.authorization.servieses.interfaces;

import jwt_token.authorization.domain.dto.LoginDto;
import jwt_token.authorization.domain.dto.TokenResponseDto;
import jwt_token.authorization.domain.dto.TokensDto;
import jwt_token.authorization.domain.dto.ValidationResponseDto;
import org.springframework.security.core.Authentication;

public interface AuthService {
    TokensDto login(LoginDto loginDto);
    TokensDto refresh(String refreshToken);
    ValidationResponseDto validation( String authorizationHeader);
    TokenResponseDto getTokenResponseDto(TokensDto tokensDto);

}
