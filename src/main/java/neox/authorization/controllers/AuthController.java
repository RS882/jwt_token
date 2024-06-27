package neox.authorization.controllers;

import jakarta.validation.Valid;
import neox.authorization.domain.dto.LoginDto;
import neox.authorization.domain.dto.TokenResponseDto;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/v1/auth")
public class AuthController {

    @PostMapping("/login")
    public ResponseEntity<TokenResponseDto> login(
            @Valid
            @RequestBody LoginDto loginDto) {

        return ResponseEntity
                .status(HttpStatus.OK)
                .body(null);
    }
}
