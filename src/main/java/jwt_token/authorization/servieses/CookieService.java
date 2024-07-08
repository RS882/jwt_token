package jwt_token.authorization.servieses;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jwt_token.authorization.exception_handler.bad_request.BadCookieException;
import org.springframework.stereotype.Service;

import java.util.Arrays;

@Service
public class CookieService {

    public static final String COOKIE_REFRESH_TOKEN_NAME = "Refresh-token";

    public void setRefreshTokenToCookie(HttpServletResponse response, String refreshToken) {
        Cookie cookie = makeCookie(COOKIE_REFRESH_TOKEN_NAME, refreshToken);
        response.addCookie(cookie);
    }

    public String getRefreshTokenFromCookie(HttpServletRequest request) {

        Cookie[] cookies = request.getCookies();

        if (cookies == null) throw new BadCookieException("Cookie not found");

        return Arrays.stream(cookies)
                .filter(cookie -> COOKIE_REFRESH_TOKEN_NAME.equals(cookie.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElseThrow(() -> new BadCookieException("Cookie is incorrect"));
    }

    public static Cookie makeCookie(String name, String value) {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setMaxAge(
                TokenService.REFRESH_TOKEN_EXPIRES_IN_MINUTES * 60);
        return cookie;
    }
}
