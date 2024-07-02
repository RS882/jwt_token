package jwt_token.authorization.servieses.mapping;

import jwt_token.authorization.domain.dto.UserDto;
import jwt_token.authorization.domain.dto.UserRegistrationDto;
import jwt_token.authorization.domain.entity.User;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;

@Mapper
public abstract class UserMapperService {

    @Autowired
    protected PasswordEncoder encoder;

    @Mapping(target = "isActive", constant = "true")
    @Mapping(target = "role", expression = "java(jwt_token.authorization.contstants.Role.ROLE_USER)")
    @Mapping(target="password", expression = "java(encoder.encode(dto.getPassword()))")
    public abstract User toEntity(UserRegistrationDto dto);

    public abstract UserDto toDto(User user);
}
