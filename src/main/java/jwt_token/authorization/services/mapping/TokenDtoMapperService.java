package jwt_token.authorization.services.mapping;

import jwt_token.authorization.domain.dto.TokenResponseDto;
import jwt_token.authorization.domain.dto.TokensDto;
import org.mapstruct.Mapper;

@Mapper
public abstract class TokenDtoMapperService {
   public abstract TokenResponseDto toResponseDto(TokensDto tokensDto) ;
}
