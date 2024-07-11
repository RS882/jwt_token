package jwt_token.authorization.services.interfaces;

import jwt_token.authorization.domain.entity.User;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface CustomUserDetailsService extends UserDetailsService {
    public void updateUser(User user) ;
}
