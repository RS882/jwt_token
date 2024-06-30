package jwt_token.authorization.domain.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class TokensDto {
    private String userId;
    private String refreshToken;
    private String accessToken;
}
