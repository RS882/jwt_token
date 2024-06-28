package neox.authorization.servieses.interfaces;

import neox.authorization.domain.dto.LoginDto;
import neox.authorization.domain.dto.TokenResponseDto;

public interface AuthService {
    TokenResponseDto login(LoginDto loginDto);
}
