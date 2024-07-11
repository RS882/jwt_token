package jwt_token.authorization.services.interfaces;

import jwt_token.authorization.domain.dto.UserDto;
import jwt_token.authorization.domain.dto.UserRegistrationDto;


public interface UserService {

    UserDto registerUser(UserRegistrationDto userRegistrationDto);

}
