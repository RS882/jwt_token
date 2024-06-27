package neox.authorization.repositorys;

import neox.authorization.domain.entity.User;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface UsersRepository extends MongoRepository<User,String > {
}
