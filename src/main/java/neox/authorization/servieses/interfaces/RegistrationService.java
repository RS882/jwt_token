package neox.authorization.servieses.interfaces;

import neox.authorization.domain.dto.UserDto;
import neox.authorization.domain.dto.UserRegistrationDto;
import neox.authorization.domain.entity.User;


public interface RegistrationService {

    UserDto registerUser(UserRegistrationDto userRegistrationDto);

    User findUserById(String id);

}
