package neox.authorization.controllers;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import neox.authorization.domain.dto.UserDto;
import neox.authorization.domain.dto.UserRegistrationDto;
import neox.authorization.servieses.interfaces.RegistrationService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/v1/registration/user")
@RequiredArgsConstructor
public class RegistrationController {

    private final RegistrationService registrationService;

    @PostMapping
    public ResponseEntity<UserDto> userRegistration(
            @Valid
            @RequestBody
            UserRegistrationDto userRegistrationDto
    ) {
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(registrationService.registerUser(userRegistrationDto));
    }
}
