package jwt_token.authorization.domain.entity;

import lombok.Builder;
import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.LocalDateTime;
import java.util.Date;

@Data
@Builder
@Document
public class RefreshToken {

    @Id
    private String id;

    private String token;

    private String userId;

    private Date expireAt;
}
