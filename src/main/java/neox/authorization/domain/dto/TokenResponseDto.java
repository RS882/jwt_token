package neox.authorization.domain.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class TokenResponseDto {

    private String userId;
    private String refreshToken;

}
