package jwt_token.authorization.servieses;

import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import jwt_token.authorization.contstants.Role;
import jwt_token.authorization.domain.dto.LoginDto;
import jwt_token.authorization.domain.dto.TokenResponseDto;
import jwt_token.authorization.domain.dto.TokensDto;
import jwt_token.authorization.domain.dto.ValidationResponseDto;
import jwt_token.authorization.domain.entity.User;
import jwt_token.authorization.exception_handler.authentication_exception.WrongTokenException;
import jwt_token.authorization.exception_handler.forbidden.LimitOfLoginsException;
import jwt_token.authorization.servieses.interfaces.AuthService;
import jwt_token.authorization.servieses.mapping.TokenDtoMapperService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Set;

import static jwt_token.authorization.servieses.TokenService.USER_ROLE_VARIABLE_NAME;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder encoder;
    private final TokenService tokenService;
    private final TokenDtoMapperService tokenDtoMapperService;
    private final CookieService cookieService;

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
    public TokensDto refresh( String inboundRefreshToken) {

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
    public ValidationResponseDto validation( String authorizationHeader) {

        String token = authorizationHeader.substring(7);
        Claims claims = tokenService.getAccessTokenClaims(token);
        User user = (User) userDetailsService.loadUserByUsername(claims.getSubject());

        return ValidationResponseDto.builder()
                .isAuthorized(true)
                .roles((List) claims.get(USER_ROLE_VARIABLE_NAME))
                .userId(user.getId())
                .build();
    }

    @Override
    public void logout(String refreshToken) {
        tokenService.removeOldRefreshToken(refreshToken);
        SecurityContextHolder.clearContext();
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
