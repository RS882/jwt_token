package jwt_token.authorization.services;

import jwt_token.authorization.exception_handler.bad_request.BadRequestException;
import lombok.RequiredArgsConstructor;
import jwt_token.authorization.domain.dto.UserDto;
import jwt_token.authorization.domain.dto.UserRegistrationDto;
import jwt_token.authorization.domain.entity.User;
import jwt_token.authorization.repositorys.UserRepository;
import jwt_token.authorization.services.interfaces.UserService;
import jwt_token.authorization.services.mapping.UserMapperService;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository repository;
    private final UserMapperService mapper;

    @Override
    public UserDto registerUser(UserRegistrationDto userRegistrationDto) {

        if(repository.existsByEmail(userRegistrationDto.getEmail()))
            throw new BadRequestException("Email address already in use");

        User newuser = repository.save(mapper.toEntity(userRegistrationDto));
        return mapper.toDto(newuser);
    }
}
