package jwt_token.authorization.services.interfaces;

import jwt_token.authorization.domain.dto.UserDto;
import jwt_token.authorization.domain.dto.UserRegistrationDto;


public interface RegistrationService {

    UserDto registerUser(UserRegistrationDto userRegistrationDto);



}
