# Authorization Service

The `Authorization Service` class handles authentication-related operations such as login, token refresh, validation, and logout for users using JWT (JSON Web Tokens).

## Endpoints

### Login

`POST /api/v1/auth/login`

Authenticates a user and returns tokens. The access token is valid for a specific number of minutes, and the refresh token (set in a cookie) is also valid for a set number of minutes.

**Parameters:**
- `loginDto` (body): Login data transfer object containing user credentials.
- `response` (HttpServletResponse): The HTTP response object.

**Responses:**
- `200 OK`: Successful login, returns a `TokenResponseDto`.
- `400 Bad Request`: Invalid input, returns a `ResponseMessageDto`.
- `401 Unauthorized`: Incorrect password or email, returns a `ResponseMessageDto`.

### Refresh Token

`GET /api/v1/auth/refresh`

Refreshes the user's access and refresh tokens and returns new tokens. The access token is valid for a specific number of minutes, and the refresh token (set in a cookie) is also valid for a set number of minutes.

**Parameters:**
- `response` (HttpServletResponse): The HTTP response object.
- `refreshToken` (cookie): The refresh token obtained from the cookie.

**Responses:**
- `200 OK`: Successful refresh, returns a `TokenResponseDto`.
- `400 Bad Request`: Cookie is incorrect, returns a `ResponseMessageDto`.
- `401 Unauthorized`: Invalid token, returns a `ResponseMessageDto`.

### Validate Token

`GET /api/v1/auth/validation`

Validates the user's access bearer token in the header authorization and returns validation information.

**Parameters:**
- `authorizationHeader` (header): The authorization header containing the bearer token.

**Responses:**
- `200 OK`: Successful validation, returns a `ValidationResponseDto`.
- `401 Unauthorized`: Invalid token, returns a `ResponseMessageDto`.

### Logout

`GET /api/v1/auth/logout`

Logs out the user by removing the refresh token from the cookie and database.

**Parameters:**
- `response` (HttpServletResponse): The HTTP response object.
- `refreshToken` (cookie): The refresh token obtained from the cookie.

**Responses:**
- `401 Unauthorized`: Invalid token, returns a `ResponseMessageDto`.

## Usage Notes

- The refresh token is stored in a cookie for security purposes.
- The access token must be included in the authorization header as a bearer token for endpoints that require validation.
- Ensure the cookie handling mechanism is properly configured in your client to store and send the refresh token when necessary.
