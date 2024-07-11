package jwt_token.authorization.controllers;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jwt_token.authorization.domain.dto.LoginDto;
import jwt_token.authorization.domain.dto.TokenResponseDto;
import jwt_token.authorization.domain.dto.TokensDto;
import jwt_token.authorization.domain.dto.ValidationResponseDto;
import jwt_token.authorization.exception_handler.dto.ResponseMessageDto;
import jwt_token.authorization.services.CookieService;
import jwt_token.authorization.services.interfaces.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import static jwt_token.authorization.services.AuthServiceImpl.MAX_COUNT_OF_LOGINS;
import static jwt_token.authorization.services.CookieService.COOKIE_REFRESH_TOKEN_NAME;
import static jwt_token.authorization.services.TokenService.ACCESS_TOKEN_EXPIRES_IN_MINUTES;
import static jwt_token.authorization.services.TokenService.REFRESH_TOKEN_EXPIRES_IN_MINUTES;

@RestController
@RequestMapping("/v1/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication controller", description = "Controller for User authentication using JWT")
public class AuthController {

    private final AuthService service;
    private final CookieService cookieService;

    @PostMapping("/login")
    @Operation(
            summary = "Login for Users and set refresh token in cookie",
            description = "Authenticates a user and returns a tokens. Access Token is valid for " + ACCESS_TOKEN_EXPIRES_IN_MINUTES + " minutes" +
                    " and Refresh Token(in cookie) is valid for " + REFRESH_TOKEN_EXPIRES_IN_MINUTES + " minutes."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Successful login",
                    content = {@Content(mediaType = "application/json",
                            schema = @Schema(implementation = TokenResponseDto.class))}
            ),
            @ApiResponse(responseCode = "400",
                    description = "Invalid input",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ResponseMessageDto.class)
                    )),
            @ApiResponse(responseCode = "401",
                    description = "Incorrect password or email",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ResponseMessageDto.class)

                    )),
            @ApiResponse(responseCode = "403",
                    description = "Count of user's logins is more than maximum(" + MAX_COUNT_OF_LOGINS + ")",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ResponseMessageDto.class)
                    ))}
    )
    public ResponseEntity<TokenResponseDto> login(
            @Valid
            @Parameter(description = "Login DTO")
            @RequestBody LoginDto loginDto,
            HttpServletResponse response) {
        TokensDto dto = service.login(loginDto);
        cookieService.setRefreshTokenToCookie(response, dto.getRefreshToken());
        return ResponseEntity.status(HttpStatus.OK).body(service.getTokenResponseDto(dto));
    }

    @GetMapping("/refresh")
    @Operation(
            summary = "Refresh user's access and refresh token",
            description = "Refresh user's access and refresh token and returns a tokens." +
                    " Access Token is valid for " + ACCESS_TOKEN_EXPIRES_IN_MINUTES + " minutes" +
                    " and Refresh Token(in cookie) is valid for " + REFRESH_TOKEN_EXPIRES_IN_MINUTES + " minutes."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Successful refresh",
                    content = {@Content(mediaType = "application/json",
                            schema = @Schema(implementation = TokenResponseDto.class))}
            ),
            @ApiResponse(responseCode = "400",
                    description = "Cookie is incorrect",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ResponseMessageDto.class)
                    )),
            @ApiResponse(responseCode = "401",
                    description = "Invalid token",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ResponseMessageDto.class)
                    ))}
    )
    public ResponseEntity<TokenResponseDto> refresh(
            HttpServletResponse response,
            @Parameter(
                    in = ParameterIn.COOKIE,
                    name = COOKIE_REFRESH_TOKEN_NAME,
                    required = true,
                    hidden = true,
                    schema = @Schema(type = "string")
            )
            @CookieValue(name = COOKIE_REFRESH_TOKEN_NAME) @NotNull String refreshToken) {
        TokensDto dto = service.refresh(refreshToken);
        cookieService.setRefreshTokenToCookie(response, dto.getRefreshToken());
        return ResponseEntity.status(HttpStatus.OK).body(service.getTokenResponseDto(dto));
    }

    @GetMapping("/validation")
    @Operation(
            summary = "Validation of user's access token",
            description = "Validation of user's access bearer token in header authorization" +
                    " and returns validation information.")
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Successful validation",
                    content = {@Content(mediaType = "application/json",
                            schema = @Schema(implementation = ValidationResponseDto.class))}
            ),
            @ApiResponse(responseCode = "401",
                    description = "Invalid token",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ResponseMessageDto.class)
                    ))})
    public ResponseEntity<ValidationResponseDto> validation(
            @Parameter(hidden = true)
            @RequestHeader(HttpHeaders.AUTHORIZATION) @NotNull String authorizationHeader) {
        return ResponseEntity.status(HttpStatus.OK).body(service.validation(authorizationHeader));
    }

    @GetMapping("/logout")
    @Operation(
            summary = "Logout of user",
            description = "Logout of user. Remove the refresh token from cookie and database")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "401",
                    description = "Invalid token",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = ResponseMessageDto.class)
                    ))})
    public void logout(
            HttpServletResponse response,
            @Parameter(
                    in = ParameterIn.COOKIE,
                    name = COOKIE_REFRESH_TOKEN_NAME,
                    required = true,
                    hidden = true,
                    schema = @Schema(type = "string")
            )
            @CookieValue(name = COOKIE_REFRESH_TOKEN_NAME) @NotNull String refreshToken) {
        service.logout(refreshToken);
        cookieService.setRefreshTokenToCookie(response, null);
    }
}
