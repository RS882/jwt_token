package jwt_token.authorization.repositorys;

import jwt_token.authorization.domain.entity.User;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

public interface UserRepository extends MongoRepository<User,String > {

    Optional<User> findByEmailAndIsActiveTrue(String email);
    void deleteAllByEmail(String email);
}
