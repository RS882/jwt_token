package neox.authorization.servieses;

import lombok.RequiredArgsConstructor;
import neox.authorization.repositorys.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username)  {

        return repository.findByEmail(username)
                .orElseThrow(()-> new UsernameNotFoundException(
                        String.format("User with email %s not found", username)));
    }
}
