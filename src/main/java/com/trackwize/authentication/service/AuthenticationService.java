package com.trackwize.authentication.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.trackwize.authentication.model.dto.*;
import com.trackwize.common.constant.ErrorConst;
import com.trackwize.authentication.mapper.UserMapper;
import com.trackwize.authentication.model.entity.User;
import com.trackwize.common.exception.TrackWizeException;
import com.trackwize.common.util.PasswordUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationService {

    @Value("${jwt.defaultAccessTokenTimeout}")
    private int defaultAccessTokenTimeout;

    @Value("${jwt.defaultRefreshTokenTimeout}")
    private int defaultRefreshTokenTimeout;

    private final TokenService tokenService;
    private final UserService userService;
    private final NotificationService notificationService;

    private final UserMapper userMapper;

    /**
     * Authenticate user and generate access and refresh tokens.
     *
     * @param reqDTO The authentication request data transfer object containing user credentials.
     * @return An AuthenticationResDTO containing the generated access and refresh tokens.
     * @throws TrackWizeException If authentication fails or there is an error during token generation.
     */
    public AuthenticationResDTO authenticateAccess(AuthenticationReqDTO reqDTO) throws TrackWizeException {
//        1. Retrieve user (throws TrackWizeException if not found)
        User user = userService.getUserByEmail(reqDTO.getEmail());

//        2. Validate password (throws TrackWizeException if invalid)
        userService.validatePassword(reqDTO, user);

//        3. Ensure no concurrent active session (throws TrackWizeException if already logged in)
        tokenService.validateNoActiveSession(user);

//        4. Generate JWT tokens
        String accessToken = tokenService.generateUserAccessToken(user, defaultAccessTokenTimeout);
        String refreshToken = tokenService.generateUserAccessToken(user, defaultRefreshTokenTimeout);

        TokenReqDTO tokenReqDTO = new TokenReqDTO();
        tokenReqDTO.setUserId(user.getUserId());
        tokenReqDTO.setAccessToken(accessToken);
        tokenReqDTO.setRefreshToken(refreshToken);

//        5. Save token record to database
        tokenService.saveTokenRecord(tokenReqDTO);

//        6. Return AuthenticationResDTO as response
        return new AuthenticationResDTO(accessToken, refreshToken);
    }


    /**
     * Validate the provided refresh token for the specified user.
     *
     * @param userId       The ID of the user.
     * @param refreshToken The refresh token to be validated.
     * @throws TrackWizeException If the refresh token is invalid.
     */
    public void validateRefreshToken(Long userId, String refreshToken) {
        boolean isValid = tokenService.validateRefreshToken(userId, refreshToken);
        if (!isValid) {
            throw new TrackWizeException(
                    ErrorConst.INVALID_REFRESH_TOKEN_CODE,
                    ErrorConst.INVALID_REFRESH_TOKEN_MSG
            );
        }
    }

    /**
     * Generate a new access token for the specified user.
     *
     * @param userId The ID of the user.
     * @return The newly generated access token.
     * @throws TrackWizeException If there is an error during token generation.
     */
    public String generateNewAccessToken(Long userId) throws TrackWizeException {
        User user = userMapper.findById(userId);
        return tokenService.generateUserAccessToken(user, defaultAccessTokenTimeout);
    }

    /**
     * Update the user's password using the provided reset request data.
     *
     * @param reqDTO The reset request data transfer object containing the reset token and new password.
     * @param token The password reset token carried from password reset process
     * @throws TrackWizeException If there is an error during password update.
     */
    public void updatePassword(PasswordResetProcessReqDTO reqDTO, String token) throws TrackWizeException {
        String email = tokenService.getRedisValueByToken(token);
        if (StringUtils.isBlank(email)){
            log.warn("[{}] due to invalid or expired reset token: [token] [{}]", ErrorConst.TOKEN_EXPIRED_CODE, token);
            throw new TrackWizeException(
                    ErrorConst.TOKEN_EXPIRED_CODE,
                    ErrorConst.TOKEN_EXPIRED_MSG
            );
        }

        User user = userMapper.findByEmail(email);
        if (user == null) {
            log.error("[{}] due to no user record found for:  [email] [{}].", ErrorConst.NO_RECORD_FOUND_CODE, email);
            throw new TrackWizeException(
                    ErrorConst.NO_RECORD_FOUND_CODE,
                    ErrorConst.NO_RECORD_FOUND_MSG
            );
        }
        user.setPassword(PasswordUtil.encryptPassword(reqDTO.getPassword()));

        int result = userMapper.updatePassword(user);
        if (result <= 0) {
            log.error("[{}] due to failure when updating new password for: [email] [{}]", ErrorConst.UPDATE_PASSWORD_FAILED_CODE, email);
            throw new TrackWizeException(
                    ErrorConst.UPDATE_PASSWORD_FAILED_CODE,
                    ErrorConst.UPDATE_PASSWORD_FAILED_MSG
            );
        }

    }

    /**
     * Generate a password reset token for the specified email.
     *
     * @param email      The email address of the user.
     * @param trackingId The tracking ID for the request.
     * @throws TrackWizeException      If there is an error during token generation.
     * @throws JsonProcessingException If there is an error processing JSON.
     */
    public void requestPasswordReset(String email, String trackingId) throws TrackWizeException, JsonProcessingException {
        String token = tokenService.generatePasswordResetToken(email);

        notificationService.sendPasswordResetEmail(email, token, trackingId);
    }

    /**
     * Logout the user by invalidating the provided refresh token.
     *
     * @param refreshToken The refresh token to be invalidated.
     */
    public void logout(String refreshToken) {
        tokenService.logout(refreshToken);
    }

}
