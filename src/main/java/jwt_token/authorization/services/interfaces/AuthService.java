package jwt_token.authorization.services.interfaces;

import jwt_token.authorization.domain.dto.LoginDto;
import jwt_token.authorization.domain.dto.TokenResponseDto;
import jwt_token.authorization.domain.dto.TokensDto;
import jwt_token.authorization.domain.dto.ValidationResponseDto;

public interface AuthService {
    TokensDto login(LoginDto loginDto);
    TokensDto refresh(String refreshToken);
    ValidationResponseDto validation( String authorizationHeader);
    void logout( String refreshToken);
    TokenResponseDto getTokenResponseDto(TokensDto tokensDto);

}
