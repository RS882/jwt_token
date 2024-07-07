package jwt_token.authorization.controllers;

import com.fasterxml.jackson.databind.ObjectMapper;
import jwt_token.authorization.domain.dto.LoginDto;
import jwt_token.authorization.domain.dto.UserRegistrationDto;
import jwt_token.authorization.servieses.mapping.UserMapperService;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;
import java.util.stream.Stream;

import static jwt_token.authorization.servieses.CookieService.COOKIE_REFRESH_TOKEN_NAME;
import static org.springframework.data.mongodb.core.query.Criteria.where;
import static org.springframework.data.mongodb.core.query.Query.query;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("Authorization integration tests: ")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@DisplayNameGeneration(value = DisplayNameGenerator.ReplaceUnderscores.class)
class AuthIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private MongoTemplate mongoTemplate;

    @Autowired
    private UserMapperService mapperService;

    private ObjectMapper mapper = new ObjectMapper();

    private String createdUserId;

    private static final String USER1_EMAIL = UUID.randomUUID() + "@example.com";
    private static final String USER1_PASSWORD = "Querty123!";

    private final String TEST_COLLECTION_NAME = "TempUsers";

    @BeforeAll
    public void setUp() {
        if (!mongoTemplate.collectionExists(TEST_COLLECTION_NAME))
            mongoTemplate.createCollection(TEST_COLLECTION_NAME);

        UserRegistrationDto dto = UserRegistrationDto
                .builder()
                .email(USER1_EMAIL)
                .password(USER1_PASSWORD)
                .build();

        createdUserId = mongoTemplate.save(
                        mapperService.toEntity(dto),
                        TEST_COLLECTION_NAME)
                .getId();
    }

    @AfterAll
    public void tearDown() {
        mongoTemplate.remove(
                query(where("_id").is(createdUserId)),
                TEST_COLLECTION_NAME);
    }

    @Nested
    @DisplayName("POST /v1/auth/login")
    class Login {

        @Test
        public void login_with_status_200() throws Exception {
            String dtoJson = mapper.writeValueAsString(
                    LoginDto.builder()
                            .email(USER1_EMAIL)
                            .password(USER1_PASSWORD)
                            .build());
            mockMvc.perform(post("/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(dtoJson))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.userId").value(createdUserId))
                    .andExpect(jsonPath("$.accessToken").isString())
                    .andExpect(cookie().exists(COOKIE_REFRESH_TOKEN_NAME));
        }

        @ParameterizedTest(name = "Тест {index}: login_with_status_400_login_data_is_incorrect [{arguments}]")
        @MethodSource("incorrectLoginData")
        public void login_with_status_400_login_data_is_incorrect(LoginDto dto) throws Exception {
            String dtoJson = mapper.writeValueAsString(dto);
            mockMvc.perform(post("/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(dtoJson))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.errors").isArray());
        }

        @ParameterizedTest(name = "Test {index}: login_with_status_404_email_or_password_is_wrong [{arguments}]")
        @MethodSource("wrongLoginData")
        public void login_with_status_404_email_or_password_is_wrong(LoginDto dto) throws Exception {
            String dtoJson = mapper.writeValueAsString(dto);
            mockMvc.perform(post("/v1/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(dtoJson))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.message").isString());
        }


        private static Stream<Arguments> incorrectLoginData() {
            return Stream.of(Arguments.of(
                            LoginDto.builder()
                                    .email("testexample?com")
                                    .password(USER1_PASSWORD)
                                    .build()),
                    Arguments.of(
                            LoginDto.builder()
                                    .password(USER1_PASSWORD)
                                    .build()),
                    Arguments.of(
                            LoginDto.builder()
                                    .email(USER1_EMAIL)
                                    .build()),
                    Arguments.of(
                            LoginDto.builder()
                                    .email(USER1_EMAIL)
                                    .password("1E")
                                    .build()),
                    Arguments.of(
                            LoginDto.builder()
                                    .email(USER1_EMAIL)
                                    .password("asdasdlDFsd90q!u023402lks@djalsdajsd#lahsdkahs$$%dllkasd")
                                    .build()),
                    Arguments.of(
                            LoginDto.builder()
                                    .email(USER1_EMAIL)
                                    .password("asdasdlweqwe")
                                    .build()),
                    Arguments.of(
                            LoginDto.builder()
                                    .email(USER1_EMAIL)
                                    .password("asda@sdlweqwe")
                                    .build()),
                    Arguments.of(
                            LoginDto.builder()
                                    .email(USER1_EMAIL)
                                    .password("asdasdlwe8qwe")
                                    .build()),
                    Arguments.of(
                            LoginDto.builder()
                                    .email(USER1_EMAIL)
                                    .password("Qsdasdlwe8qwe")
                                    .build()),
                    Arguments.of(
                            LoginDto.builder()
                                    .email("testexample?com")
                                    .password("Qsdasdlwe8qwe")
                                    .build())
            );
        }


        private static Stream<Arguments> wrongLoginData() {
            return Stream.of(
                    Arguments.of(
                            LoginDto.builder()
                                    .email(UUID.randomUUID() + "@example.com")
                                    .password(USER1_PASSWORD)
                                    .build()),
                    Arguments.of(
                            LoginDto.builder()
                                    .email(USER1_EMAIL)
                                    .password("doIusjn%70")
                                    .build())
            );
        }
    }

}