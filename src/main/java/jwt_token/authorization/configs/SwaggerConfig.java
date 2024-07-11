package jwt_token.authorization.configs;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;

@OpenAPIDefinition(
        info = @Info(
                title = "Authorization service",
                description = "API for authorization, authentication, validation of users",
                version = "1.0.0"
        )
)
public class SwaggerConfig {
}
