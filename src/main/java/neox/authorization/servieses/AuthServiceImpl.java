package neox.authorization.servieses;

import lombok.RequiredArgsConstructor;
import neox.authorization.domain.dto.LoginDto;
import neox.authorization.domain.dto.TokenResponseDto;
import neox.authorization.servieses.interfaces.AuthService;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import neox.authorization.domain.entity.User;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final CustomUserDetailsService userDetailsService;
    private final PasswordEncoder encoder;

    @Override
    public TokenResponseDto login(LoginDto loginDto) {
        String email = loginDto.getEmail();
        User user = (User) userDetailsService.loadUserByUsername(email);
        if (!encoder.matches(loginDto.getPassword(), user.getPassword()))
            throw new BadCredentialsException("Wrong password");

        return null;
    }
}
