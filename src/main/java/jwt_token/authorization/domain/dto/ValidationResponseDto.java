package jwt_token.authorization.domain.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class ValidationResponseDto {
    private String userId;
    Boolean isAuthorized;
    List<String> roles;
}
