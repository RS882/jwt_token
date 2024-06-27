package neox.authorization.domain.entity;

import lombok.Builder;
import lombok.Data;
import neox.authorization.contstants.Role;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Data
@Builder
@Document("TempUsers")
public class User {

    @Id
    private String id;

    private String email;

    private String password;

    private Role role;

    private Boolean isActive;

}
