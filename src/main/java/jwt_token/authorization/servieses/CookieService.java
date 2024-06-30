package jwt_token.authorization.servieses;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Service;

@Service
public class CookieService {

    public static final String COOKIE_REFRESH_TOKEN_NAME = "Refresh-token";

    public void setRefreshTokenToCookie(HttpServletResponse response, String refreshToken) {
        Cookie cookie = new Cookie(COOKIE_REFRESH_TOKEN_NAME, refreshToken);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setMaxAge(TokenService.REFRESH_TOKEN_EXPIRES_IN_MINUTES * 60);

        if (refreshToken == null) cookie.setMaxAge(0);

        response.addCookie(cookie);
    }
}
