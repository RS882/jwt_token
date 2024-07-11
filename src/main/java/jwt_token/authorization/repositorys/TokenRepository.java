package jwt_token.authorization.repositorys;

import jwt_token.authorization.domain.entity.RefreshToken;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends MongoRepository<RefreshToken, String> {

    Optional<List<RefreshToken>> findByUserId(String id);

    void deleteAllByToken(String token);

    void deleteAllByUserId(String id);
}
