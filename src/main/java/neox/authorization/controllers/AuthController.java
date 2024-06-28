package neox.authorization.controllers;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import neox.authorization.domain.dto.LoginDto;
import neox.authorization.domain.dto.TokenResponseDto;
import neox.authorization.servieses.interfaces.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService service;

    @PostMapping("/login")
    public ResponseEntity<TokenResponseDto> login(
            @Valid
            @RequestBody LoginDto loginDto) {

        return ResponseEntity
                .status(HttpStatus.OK)
                .body(service.login(loginDto));
    }
}
