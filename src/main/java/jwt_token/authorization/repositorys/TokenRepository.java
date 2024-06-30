package jwt_token.authorization.repositorys;

import jwt_token.authorization.domain.entity.RefreshToken;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface TokenRepository extends MongoRepository<RefreshToken, String> {
}
