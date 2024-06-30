package jwt_token.authorization.controllers;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jwt_token.authorization.domain.dto.TokensDto;
import jwt_token.authorization.servieses.CookieService;
import lombok.RequiredArgsConstructor;
import jwt_token.authorization.domain.dto.LoginDto;
import jwt_token.authorization.domain.dto.TokenResponseDto;
import jwt_token.authorization.servieses.interfaces.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService service;
    private final CookieService cookieService;

    @PostMapping("/login")
    public ResponseEntity<TokenResponseDto> login(
            @Valid
            @RequestBody LoginDto loginDto,
            HttpServletResponse response) {

        TokensDto dto = service.login(loginDto);
        cookieService.setRefreshTokenToCookie(response, dto.getRefreshToken());

        return ResponseEntity.status(HttpStatus.OK).body(service.getTokenResponseDto(dto));
    }
}
