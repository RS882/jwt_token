package jwt_token.authorization.servieses;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jwt_token.authorization.domain.entity.RefreshToken;
import jwt_token.authorization.domain.entity.User;
import jwt_token.authorization.repositorys.TokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

@Service
public class TokenService {

    private final SecretKey accessKey;
    private final SecretKey refreshKey;

    public static final int ACCESS_TOKEN_EXPIRES_IN_MINUTES = 15;
    public static final int REFRESH_TOKEN_EXPIRES_IN_MINUTES = 15 * 24 * 60;
    public static final String USER_ROLE_VARIABLE_NAME = "role";
    public static final String USER_EMAIL_VARIABLE_NAME = "email";

    private static final String TOKENS_ISSUER = "Authorization";

    private final TokenRepository repository;

    private Date refreshTokenExpireAt;

    public TokenService(@Value("${key.access}") String accessKey, @Value("${key.refresh}") String refreshKey, TokenRepository repository) {
        this.accessKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(accessKey));
        this.refreshKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(refreshKey));
        this.repository = repository;
    }

    public String generateAccessToken(User user) {
        return Jwts.builder()
                .subject(user.getEmail())
                .expiration(getExpirationDate(ACCESS_TOKEN_EXPIRES_IN_MINUTES))
                .issuer(TOKENS_ISSUER)
                .issuedAt(Date.from(Instant.now()))
                .signWith(accessKey)
                .claim(USER_ROLE_VARIABLE_NAME, user.getAuthorities())
                .claim(USER_EMAIL_VARIABLE_NAME, user.getEmail())
                .compact();
    }

    public String generateRefreshToken(User user) {
        this.refreshTokenExpireAt = getExpirationDate(REFRESH_TOKEN_EXPIRES_IN_MINUTES);
        return Jwts.builder()
                .subject(user.getEmail())
                .expiration(this.refreshTokenExpireAt)
                .issuer(TOKENS_ISSUER)
                .issuedAt(Date.from(Instant.now()))
                .signWith(refreshKey)
                .compact();
    }

    public void saveRefreshToken(String refreshToken, String userId) {
        RefreshToken refreshTokenEntity = RefreshToken.builder()
                .token(refreshToken)
                .userId(userId)
                .expireAt(LocalDateTime.from(this.refreshTokenExpireAt.toInstant()))
                .build();
        repository.save(refreshTokenEntity);
    }

    private Date getExpirationDate(int expiresInMinutes) {
        return Date.from(LocalDateTime.now()
                .plusMinutes(expiresInMinutes)
                .atZone(ZoneId.systemDefault())
                .toInstant());
    }
}
