package jwt_token.authorization.domain.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@Schema(name = "JSON Access Web Token")
public class TokenResponseDto {
    @Schema(description = "User id", example = "668c1143a70d9e5b0d94f488")
    private String userId;

    @Schema(description = "Access token",
            example = "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ0ZXN0dXNlcjFAbWFpbC5jb20iLCJleHAiOjE3MjA3MDEyNzQsImlzcyI6IkF1dGhvcml6YXRpb24iLCJpYXQiOjE3MjA2OTk0NzQsInJvbGUiOlsiUk9MRV9VU0VSIl0sImVtYWlsIjoidGVzdHVzZXIxQG1haWwuY29tIn0.S6QwOKRtYcii5rSwrnUoKCvJAhHiSrZmi59Mhjn-yRI7xA3rEUPQw5gg-w")
    private String accessToken;
}
