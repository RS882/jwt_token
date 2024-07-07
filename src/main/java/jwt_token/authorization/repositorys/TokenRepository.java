package jwt_token.authorization.repositorys;

import jwt_token.authorization.domain.entity.RefreshToken;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;
import java.util.Set;

public interface TokenRepository extends MongoRepository<RefreshToken, String> {

    Optional<Set<RefreshToken>> findByUserId(String id);

    void deleteAllByToken(String token);
}
