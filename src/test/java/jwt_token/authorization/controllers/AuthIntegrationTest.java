package jwt_token.authorization.controllers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import jwt_token.authorization.domain.dto.LoginDto;
import jwt_token.authorization.domain.dto.UserRegistrationDto;
import jwt_token.authorization.servieses.TokenService;
import jwt_token.authorization.servieses.mapping.UserMapperService;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.UUID;
import java.util.stream.Stream;

import static jwt_token.authorization.servieses.AuthServiceImpl.MAX_COUNT_OF_LOGINS;
import static jwt_token.authorization.servieses.CookieService.COOKIE_REFRESH_TOKEN_NAME;
import static jwt_token.authorization.servieses.CookieService.makeCookie;
import static org.springframework.data.mongodb.core.query.Criteria.where;
import static org.springframework.data.mongodb.core.query.Query.query;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
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

    @Autowired
    private TokenService tokenService;

    private ObjectMapper mapper = new ObjectMapper();

    private String createdUserId1;

    private static final String USER1_EMAIL = UUID.randomUUID() + "@example.com";
    private static final String USER1_PASSWORD = "Querty123!";

    private final String TEST_COLLECTION_NAME = "TempUsers";
    private final String TEST_TOKEN_COLLECTION_NAME = "RefreshToken";


    private final String LOGIN_URL = "/v1/auth/login";
    private final String REFRESH_URL = "/v1/auth/refresh";
    private final String VALIDATION_URL = "/v1/auth/validation";
    private final String LOGOUT_URL = "/v1/auth/logout";

    @BeforeAll
    public void setUp() {
        if (!mongoTemplate.collectionExists(TEST_COLLECTION_NAME))
            mongoTemplate.createCollection(TEST_COLLECTION_NAME);

        UserRegistrationDto dto = UserRegistrationDto
                .builder()
                .email(USER1_EMAIL)
                .password(USER1_PASSWORD)
                .build();

        createdUserId1 = mongoTemplate.save(
                        mapperService.toEntity(dto),
                        TEST_COLLECTION_NAME)
                .getId();
    }

    @AfterAll
    public void tearDown() {
        mongoTemplate.remove(
                query(where("_id").is(createdUserId1)),
                TEST_COLLECTION_NAME);
        mongoTemplate.remove(
                query(where("userId").is(createdUserId1)),
                TEST_TOKEN_COLLECTION_NAME);
    }

    private void _401_header_authorization_is_null(String path) throws Exception {
        mockMvc.perform(get(path))
                .andExpect(status().isUnauthorized());
    }

    private void _401_header_authorization_is_not_bearer(String path) throws Exception {
        mockMvc.perform(get(path)
                        .header(HttpHeaders.AUTHORIZATION, "Test " + getAccessToken()))
                .andExpect(status().isUnauthorized());
    }

    private void _401_token_is_incorrect(String path) throws Exception {
        mockMvc.perform(get(path)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + "WRonG!TeSt%TokeN234"))
                .andExpect(status().isUnauthorized());
    }

    private Cookie getCookie() throws Exception {
        String dtoJson = mapper.writeValueAsString(
                LoginDto.builder()
                        .email(USER1_EMAIL)
                        .password(USER1_PASSWORD)
                        .build());
        MvcResult result = mockMvc.perform(post(LOGIN_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(dtoJson))
                .andExpect(status().isOk())
                .andReturn();
        return result.getResponse().getCookie(COOKIE_REFRESH_TOKEN_NAME);
    }

    private String getAccessToken(String email, String password) throws Exception {
        String dtoJson = mapper.writeValueAsString(
                LoginDto.builder()
                        .email(email)
                        .password(password)
                        .build());
        MvcResult result = mockMvc.perform(post(LOGIN_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(dtoJson))
                .andExpect(status().isOk())
                .andReturn();
        String responseToken = result.getResponse().getContentAsString();
        JsonNode jsonNodeToken = mapper.readTree(responseToken);
        return jsonNodeToken.get("accessToken").asText();
    }

    private String getAccessToken() throws Exception {
        return getAccessToken(USER1_EMAIL, USER1_PASSWORD);
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
            mockMvc.perform(post(LOGIN_URL)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(dtoJson))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.userId").value(createdUserId1))
                    .andExpect(jsonPath("$.accessToken").isString())
                    .andExpect(cookie().exists(COOKIE_REFRESH_TOKEN_NAME));
        }

        @ParameterizedTest(name = "Тест {index}: login_with_status_400_login_data_is_incorrect [{arguments}]")
        @MethodSource("incorrectLoginData")
        public void login_with_status_400_login_data_is_incorrect(LoginDto dto) throws Exception {
            String dtoJson = mapper.writeValueAsString(dto);
            mockMvc.perform(post(LOGIN_URL)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(dtoJson))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.errors").isArray());
        }

        @ParameterizedTest(name = "Test {index}: login_with_status_404_email_or_password_is_wrong [{arguments}]")
        @MethodSource("wrongLoginData")
        public void login_with_status_401_email_or_password_is_wrong(LoginDto dto) throws Exception {
            String dtoJson = mapper.writeValueAsString(dto);
            mockMvc.perform(post(LOGIN_URL)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(dtoJson))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.message").isString());
        }

        @Test
        public void login_with_status_403_count_of_logins_is_more_than_maximum() throws Exception {
            UUID random = UUID.randomUUID();
            UserRegistrationDto dto = UserRegistrationDto
                    .builder()
                    .email(random + "@example.com")
                    .password(USER1_PASSWORD)
                    .build();

            String createdUserId2 = mongoTemplate.save(
                            mapperService.toEntity(dto),
                            TEST_COLLECTION_NAME)
                    .getId();

            String dtoJson = mapper.writeValueAsString(
                    LoginDto.builder()
                            .email(random + "@example.com")
                            .password(USER1_PASSWORD)
                            .build());
            for (int i = 0; i < MAX_COUNT_OF_LOGINS; i++) {
                mockMvc.perform(post(LOGIN_URL)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(dtoJson))
                        .andExpect(status().isOk());
            }

            mockMvc.perform(post(LOGIN_URL)
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(dtoJson))
                    .andExpect(status().isForbidden());

            mongoTemplate.remove(
                    query(where("_id").is(createdUserId2)),
                    TEST_COLLECTION_NAME);
            mongoTemplate.remove(
                    query(where("userId").is(createdUserId2)),
                    TEST_TOKEN_COLLECTION_NAME);
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

    @Nested
    @DisplayName("GET /v1/auth/refresh")
    class Refresh {

        @Test
        public void refresh_with_status_200() throws Exception {

            mockMvc.perform(get(REFRESH_URL)
                            .cookie(getCookie()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.userId").value(createdUserId1))
                    .andExpect(jsonPath("$.accessToken").isString())
                    .andExpect(cookie().exists(COOKIE_REFRESH_TOKEN_NAME));
        }

        @Test
        public void refresh_with_status_404_cookie_is_null() throws Exception {
            mockMvc.perform(get(REFRESH_URL))
                    .andExpect(status().isBadRequest());
        }

        @Test
        public void refresh_with_status_404_cookie_is_incorrect() throws Exception {
            Cookie cookie = makeCookie("test", "test");
            mockMvc.perform(get(REFRESH_URL)
                            .cookie(cookie))
                    .andExpect(status().isBadRequest());
        }

        @Test
        public void refresh_with_status_401_token_is_incorrect() throws Exception {
            Cookie cookie = makeCookie(COOKIE_REFRESH_TOKEN_NAME, "test");
            mockMvc.perform(get(REFRESH_URL)
                            .cookie(cookie))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        public void refresh_with_status_401_token_is_invalid() throws Exception {
            Cookie cookie = getCookie();
            String refreshToken = cookie.getValue();
            tokenService.removeOldRefreshToken(refreshToken);
            mockMvc.perform(get(REFRESH_URL)
                            .cookie(cookie))
                    .andExpect(status().isUnauthorized());
        }
    }

    @Nested
    @DisplayName("GET /v1/auth/validation")
    class Validation {

        @Test
        public void validation_with_status_200() throws Exception {
            mockMvc.perform(get(VALIDATION_URL)
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + getAccessToken()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.userId").value(createdUserId1))
                    .andExpect(jsonPath("$.isAuthorized").value(true))
                    .andExpect(jsonPath("$.roles").isArray());
        }

        @Test
        public void validation_with_status_401_header_authorization_is_null() throws Exception {
            _401_header_authorization_is_null(VALIDATION_URL);
        }

        @Test
        public void validation_with_status_401_header_authorization_is_not_bearer() throws Exception {
            _401_header_authorization_is_not_bearer(VALIDATION_URL);
        }

        @Test
        public void validation_with_status_401_token_is_incorrect() throws Exception {
            _401_token_is_incorrect(VALIDATION_URL);
        }

    }

    @Nested
    @DisplayName("GET /v1/auth/logout")
    class Logout {

        @Test
        public void logout_with_status_200() throws Exception {
            Cookie cookie = getCookie();
            mockMvc.perform(get(LOGOUT_URL)
                            .cookie(cookie)
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + getAccessToken()))
                    .andExpect(status().isOk())
                    .andExpect(cookie().value(COOKIE_REFRESH_TOKEN_NAME, (String) null))
                    .andReturn();
        }

        @Test
        public void logout_with_status_401_header_authorization_is_null() throws Exception {
            _401_header_authorization_is_null(LOGOUT_URL);
        }

        @Test
        public void logout_with_status_401_header_authorization_is_not_bearer() throws Exception {
            _401_header_authorization_is_not_bearer(LOGOUT_URL);
        }

        @Test
        public void logout_with_status_401_token_is_incorrect() throws Exception {
            _401_token_is_incorrect(LOGOUT_URL);
        }

    }
}