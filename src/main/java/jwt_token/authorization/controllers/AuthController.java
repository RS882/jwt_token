package jwt_token.authorization.controllers;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jwt_token.authorization.domain.dto.TokensDto;
import jwt_token.authorization.domain.dto.ValidationResponseDto;
import jwt_token.authorization.servieses.CookieService;
import lombok.RequiredArgsConstructor;
import jwt_token.authorization.domain.dto.LoginDto;
import jwt_token.authorization.domain.dto.TokenResponseDto;
import jwt_token.authorization.servieses.interfaces.AuthService;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
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

    @GetMapping("/refresh")
    public ResponseEntity<TokenResponseDto> refresh(
            HttpServletRequest request,
            HttpServletResponse response) {

        String refreshToken = cookieService.getRefreshTokenFromCookie(request);
        TokensDto dto = service.refresh(refreshToken);
        cookieService.setRefreshTokenToCookie(response, dto.getRefreshToken());

        return ResponseEntity.status(HttpStatus.OK).body(service.getTokenResponseDto(dto));
    }

    @GetMapping("/validation")
    public ResponseEntity<ValidationResponseDto> validation(

            @RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader) {

        ValidationResponseDto dto = service.validation( authorizationHeader);

        return ResponseEntity.status(HttpStatus.OK).body(dto);
    }
}
