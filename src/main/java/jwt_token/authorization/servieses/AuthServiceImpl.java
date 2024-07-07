package jwt_token.authorization.servieses;

import io.jsonwebtoken.Claims;
import jwt_token.authorization.domain.dto.LoginDto;
import jwt_token.authorization.domain.dto.TokenResponseDto;
import jwt_token.authorization.domain.dto.TokensDto;
import jwt_token.authorization.domain.entity.User;
import jwt_token.authorization.exception_handler.authentication_exception.WrongTokenException;
import jwt_token.authorization.exception_handler.forbidden.LimitOfLoginsException;
import jwt_token.authorization.servieses.interfaces.AuthService;
import jwt_token.authorization.servieses.mapping.TokenDtoMapperService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder encoder;
    private final TokenService tokenService;
    private final TokenDtoMapperService tokenDtoMapperService;

    public static final int MAX_COUNT_OF_LOGINS = 5;

    @Override
    public TokensDto login(LoginDto loginDto) {
        String email = loginDto.getEmail();
        User user = (User) userDetailsService.loadUserByUsername(email);
        if (!encoder.matches(loginDto.getPassword(), user.getPassword()))
            throw new BadCredentialsException("Wrong password");
        checkCountOfLogins(user.getId());
        return tokenService.getTokens(user);
    }

    @Override
    public TokensDto refresh(String inboundRefreshToken) {
        if (!tokenService.validateRefreshToken(inboundRefreshToken))
            throw new WrongTokenException("Token is incorrect");

        Claims claims = tokenService.getRefreshTokenClaims(inboundRefreshToken);
        User user = (User) userDetailsService.loadUserByUsername(claims.getSubject());
        List<String> refreshTokens = tokenService.getRefreshTokensByUserId(user.getId());

        if (!refreshTokens.contains(inboundRefreshToken))
            throw new WrongTokenException("Token is wrong");

        TokensDto tokensDto = tokenService.getTokens(user);
        tokenService.removeOldRefreshToken(inboundRefreshToken);
        return tokensDto;
    }

    @Override
    public TokenResponseDto getTokenResponseDto(TokensDto tokensDto) {
        return tokenDtoMapperService.toResponseDto(tokensDto);
    }

    private  void checkCountOfLogins(String userId) {
        int currentCount = tokenService.getRefreshTokensByUserId(userId).size();

        if (currentCount >= MAX_COUNT_OF_LOGINS)
            throw new LimitOfLoginsException(userId);

    }
}
