package jwt_token.authorization.servieses.interfaces;

import jwt_token.authorization.domain.dto.LoginDto;
import jwt_token.authorization.domain.dto.TokenResponseDto;
import jwt_token.authorization.domain.dto.TokensDto;

public interface AuthService {
    TokensDto login(LoginDto loginDto);
    TokensDto refresh(String refreshToken);
    TokenResponseDto getTokenResponseDto(TokensDto tokensDto);
}
