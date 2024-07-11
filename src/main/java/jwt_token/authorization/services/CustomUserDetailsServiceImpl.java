package jwt_token.authorization.services;

import jwt_token.authorization.domain.entity.User;
import jwt_token.authorization.services.interfaces.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import jwt_token.authorization.repositorys.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class CustomUserDetailsServiceImpl implements CustomUserDetailsService {

    private final UserRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username)  {

        return repository.findByEmailAndIsActiveTrue(username)
                .orElseThrow(()-> new UsernameNotFoundException(
                        String.format("User with email %s not found", username)));
    }

    @Override
    public void updateUser(User user) {
        repository.save(user);
    }
}
