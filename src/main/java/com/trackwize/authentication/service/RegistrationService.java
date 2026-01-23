package com.trackwize.authentication.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.trackwize.authentication.mapstruct.UserMapStruct;
import com.trackwize.authentication.model.dto.UserRegistrationReqDTO;
import com.trackwize.authentication.model.entity.User;
import com.trackwize.common.constant.DBConst;
import com.trackwize.common.constant.ErrorConst;
import com.trackwize.common.exception.TrackWizeException;
import com.trackwize.common.util.PasswordUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Slf4j
@Service
@RequiredArgsConstructor
public class RegistrationService {

    private final UserService userService;
    private final NotificationService notificationService;
    private final TokenService tokenService;

    private final UserMapStruct userMapStruct;

    public void submitUserRegistration(
            UserRegistrationReqDTO reqDTO,
            String trackingId
    ) throws JsonProcessingException {
        String encryptedPassword = PasswordUtil.encryptPassword(reqDTO.getPassword());

        boolean emailExists  = userService.isEmailExists(reqDTO.getEmail());
        if (emailExists) {
            log.warn("[{}] due to email already exist in database: [email] [{}]", ErrorConst.TOKEN_EXPIRED_CODE, reqDTO.getEmail());
            throw new TrackWizeException(
                    ErrorConst.CREATE_USER_FAILED_CODE,
                    reqDTO.getEmail() + " is already in used"
            );
        }

        User user = userMapStruct.toEntity(reqDTO);
        user.setPassword(encryptedPassword);
        user.setStatus(DBConst.STATUS_PENDING_CREATE);
        user.setCreatedBy(DBConst.USER_ID_SYSTEM);
        user.setUpdatedBy(DBConst.USER_ID_SYSTEM);

        userService.create(user);

        notificationService.sendAccountIsCreatedEmail(user.getEmail(), user.getName(), trackingId);

        handleAccountVerification(user, reqDTO, trackingId);
    }

    private void handleAccountVerification(
            User user,
            UserRegistrationReqDTO reqDTO,
            String trackingId
    ) throws JsonProcessingException {
        String token = tokenService.generateEmailVerificationToken(reqDTO.getEmail());

        notificationService.sendAccountIsVerifiedEmail(user.getEmail(), user.getName(), token, trackingId);
    }

    public void verifyAccount(String token, String trackingId) throws JsonProcessingException {
        String email = tokenService.getRedisValueByToken(token);

        if (StringUtils.isBlank(email)) {
            log.warn("[{}] due to invalid or expired reset token: [token] [{}]", ErrorConst.TOKEN_EXPIRED_CODE, token);
            throw new TrackWizeException(
                    ErrorConst.TOKEN_EXPIRED_CODE,
                    ErrorConst.TOKEN_EXPIRED_MSG
            );
        }

        userService.activateUserAccount(email);

        notificationService.sendAccountIsActivateEmail(email, trackingId);
    }
}
