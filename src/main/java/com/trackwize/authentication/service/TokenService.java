package com.trackwize.authentication.service;

import com.trackwize.common.constant.ErrorConst;
import com.trackwize.common.constant.TokenConst;
import com.trackwize.authentication.mapper.TokenMapper;
import com.trackwize.authentication.mapstruct.TokenMapStruct;
import com.trackwize.authentication.model.dto.TokenReqDTO;
import com.trackwize.authentication.model.entity.Token;
import com.trackwize.authentication.model.entity.User;
import com.trackwize.common.exception.TrackWizeException;
import com.trackwize.common.util.JWTUtil;
import com.trackwize.common.util.OpaqueUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenService {

    private final TokenMapper tokenMapper;
    private final TokenMapStruct tokenMapStruct;
    private final JWTUtil jwtUtil;
    private final RedisTemplate<String, String> redisTemplate;

    /**
     * Generate a JWT token for the given user with specified timeout.
     *
     * @param user               The user for whom the token is to be generated.
     * @param accessTokenTimeout The timeout duration for the access token in minutes.
     * @return The generated JWT token as a String.
     * @throws TrackWizeException If there is an error during token generation.
     */
    public String generateUserAccessToken(User user, int accessTokenTimeout) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("name", user.getName());
        claims.put("email", user.getEmail());

        String token = jwtUtil.generateToken(claims, user.getUserId().toString(), accessTokenTimeout);
        if (StringUtils.isBlank(token)) {
            log.error("{} due to Token generation return null.", ErrorConst.GENERATE_TOKEN_ERROR_CODE);
            throw new TrackWizeException(
                    ErrorConst.GENERATE_TOKEN_ERROR_CODE,
                    ErrorConst.GENERATE_TOKEN_ERROR_MSG
            );
        }
        return token;
    }

    /**
     * Save or update the token record in the database.
     *
     * @param tokenReqDTO The token request data transfer object containing token details.
     * @throws TrackWizeException If there is an error during the persistence of the token record.
     */
    public void saveTokenRecord(TokenReqDTO tokenReqDTO) {
        Token token = tokenMapStruct.toEntity(tokenReqDTO);

        int result;
        boolean isTokenExist = tokenMapper.isExist(token.getUserId());
        if (isTokenExist) {
            token.setUpdatedBy(tokenReqDTO.getUserId());
            result = tokenMapper.update(token);
            if (result <= 0) {
                log.error("{} due to failure when updating token record for: [tokenReqDTO] [{}]", ErrorConst.PERSIST_TOKEN_ERROR_CODE, tokenReqDTO);
                throw new TrackWizeException(
                        ErrorConst.PERSIST_TOKEN_ERROR_CODE,
                        ErrorConst.PERSIST_TOKEN_ERROR_MSG
                );
            }
        }

        token.setCreatedBy(tokenReqDTO.getUserId());
        result = tokenMapper.create(token);
        if (result <= 0) {
            log.error("{} due to failure when creating token record for: [tokenReqDTO] [{}]", ErrorConst.PERSIST_TOKEN_ERROR_CODE, tokenReqDTO);
            throw new TrackWizeException(
                    ErrorConst.PERSIST_TOKEN_ERROR_CODE,
                    ErrorConst.PERSIST_TOKEN_ERROR_MSG
            );
        }
    }

    /**
     * Validate that the user does not have an active session.
     *
     * @param user The user to be validated.
     * @throws TrackWizeException If the user already has an active session.
     */
    public void validateNoActiveSession(User user) {
        Token token = tokenMapper.findByUserId(user.getUserId());
        if (token == null) {
            log.error("{} due to no Token record found in database for: [user_id] [{}]", ErrorConst.NO_RECORD_FOUND_CODE, user.getUserId());
            throw new TrackWizeException(
                    ErrorConst.NO_RECORD_FOUND_CODE,
                    ErrorConst.NO_RECORD_FOUND_MSG
            );
        }

        boolean result = jwtUtil.validateToken(token.getAccessToken());
        if (!result) {
            log.warn("{} due to user already has an active session: [user_id] [{}]", ErrorConst.USER_ALREADY_LOGGED_IN_CODE, user.getUserId());
            throw new TrackWizeException(
                    ErrorConst.USER_ALREADY_LOGGED_IN_CODE,
                    ErrorConst.USER_ALREADY_LOGGED_IN_MSG
            );
        }

    }

    /**
     * Find the token record by user ID.
     *
     * @param userId The ID of the user.
     * @return The Token entity associated with the user ID.
     */
    public Token findByUserId(Long userId) {
        return tokenMapper.findByUserId(userId);
    }

    /**
     * Logs out the user by invalidating the provided refresh token.
     *
     * @param refreshToken The refresh token to be invalidated.
     */
    public void logout(String refreshToken) {
        Token token = tokenMapper.validateToken(refreshToken);
        if (token != null) {
            tokenMapper.deleteById(token.getTokenId());
        }
    }

    /**
     * Generate a password reset token for the specified email.
     * Send the password reset link to the user email.
     *
     * @param email      The email address of the user.
     * @return The generated password reset token.
     * @throws TrackWizeException      If there is an error during token generation.
     */
    public String generatePasswordResetToken(String email) throws TrackWizeException {
//        1. Generate JWT-based password reset token
        String token = jwtUtil.generateToken(null, email, TokenConst.RESET_PASSWORD_TOKEN_EXPIRY);
        if (token == null) {
            log.error("[{}] due to failure when generating token for: [email] [{}]", ErrorConst.GENERATE_TOKEN_ERROR_CODE, email);
            throw new TrackWizeException(
                    ErrorConst.GENERATE_TOKEN_ERROR_CODE,
                    ErrorConst.GENERATE_TOKEN_ERROR_MSG
            );
        }
//        2. Store token→email mapping in Redis with expiry
        redisTemplate.opsForValue().set(token, email, TokenConst.RESET_PASSWORD_TOKEN_EXPIRY, TimeUnit.MINUTES);

//        3. return token as response
        return token;
    }

    public String getRedisValueByToken(String token) {
        return redisTemplate.opsForValue().get(token);
    }

    /**
     * Validates the provided refresh token for the given userId.
     *
     * @param userId       The ID of the user.
     * @param refreshToken The refresh token to be validated.
     * @return true if the refresh token is valid; false otherwise.
     */
    public boolean validateRefreshToken(Long userId, String refreshToken) {
//        1. Check if the userId from the token matches the provided userId
        Long tokenUserId = jwtUtil.getSubject(refreshToken);
        if (!tokenUserId.equals(userId)) {
            log.warn("UserId from token does not match the provided userId: [user_id] [{}]", userId);
            return false;
        }

//        2. Retrieve stored token for the user
        Token token = findByUserId(userId);

//        3. Check if the stored refresh token matches the provided token
        if (!token.getRefreshToken().equals(refreshToken)) {
            log.warn("Refresh token does not match the stored token: [refresh_token] [{}]", refreshToken);
            return false;
        }

//        4. Check if the token is valid (not expired, correct signature)
        boolean isValid = jwtUtil.validateToken(refreshToken);
        if (!isValid) {
            log.warn("Refresh token is not valid or has expired: [refresh_token] [{}]", refreshToken);
            return false;
        }

        return true;
    }

    public String generateEmailVerificationToken(String email) throws TrackWizeException {
//        1. Generate Opaque password reset token
        String token = OpaqueUtil.generate();

//        2. Store token→email mapping in Redis with expiry
        redisTemplate.opsForValue().set(token, email, TokenConst.ACCOUNT_VERIFICATION_TOKEN_EXPIRY, TimeUnit.MINUTES);

//        3. return token as response
        return token;
    }
}
