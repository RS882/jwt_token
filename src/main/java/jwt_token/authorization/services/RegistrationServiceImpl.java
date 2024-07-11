package jwt_token.authorization.services;

import lombok.RequiredArgsConstructor;
import jwt_token.authorization.domain.dto.UserDto;
import jwt_token.authorization.domain.dto.UserRegistrationDto;
import jwt_token.authorization.domain.entity.User;
import jwt_token.authorization.repositorys.UserRepository;
import jwt_token.authorization.services.interfaces.RegistrationService;
import jwt_token.authorization.services.mapping.UserMapperService;
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

}
