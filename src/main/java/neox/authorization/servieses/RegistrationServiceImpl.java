package neox.authorization.servieses;

import lombok.RequiredArgsConstructor;
import neox.authorization.domain.dto.UserDto;
import neox.authorization.domain.dto.UserRegistrationDto;
import neox.authorization.domain.entity.User;
import neox.authorization.repositorys.UserRepository;
import neox.authorization.servieses.interfaces.RegistrationService;
import neox.authorization.servieses.mapping.UserMapperService;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RegistrationServiceImpl implements RegistrationService {

    private final UserRepository repository;
    private final UserMapperService mapper;

    @Override
    public UserDto registerUser(UserRegistrationDto userRegistrationDto) {

        User newuser = repository.save(mapper.toEntity(userRegistrationDto));
        return mapper.toDto(newuser);
    }

    @Override
    public User findUserById(String id) {
        return repository.findById(id).orElse(null);
    }
}
