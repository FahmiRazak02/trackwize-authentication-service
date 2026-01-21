package com.trackwize.authentication.service;

import com.trackwize.common.constant.DBConst;
import com.trackwize.common.constant.ErrorConst;
import com.trackwize.authentication.mapper.UserMapper;
import com.trackwize.authentication.model.dto.AuthenticationReqDTO;
import com.trackwize.authentication.model.entity.User;
import com.trackwize.common.exception.TrackWizeException;
import com.trackwize.common.util.PasswordUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserMapper userMapper;

    public User getUserByEmail(String email) {
        User user = userMapper.findByEmail(email);

        if (user == null) {
            log.error("[{}] due to no user record found for: [email] [{}]",
                    ErrorConst.NO_RECORD_FOUND_CODE,
                    email
            );

            throw new TrackWizeException(
                    ErrorConst.NO_RECORD_FOUND_CODE,
                    ErrorConst.NO_RECORD_FOUND_MSG
            );
        }

        return user;
    }

    public void validatePassword(AuthenticationReqDTO reqDTO, User user) {
        boolean isPasswordMatch = PasswordUtil.isPasswordMatch(reqDTO.getPassword(), user.getPassword());

        if (!isPasswordMatch) {
            log.warn("[{}] due to password is not match", ErrorConst.NO_RECORD_FOUND_CODE);

            throw new TrackWizeException(
                    ErrorConst.INVALID_CREDENTIALS_CODE,
                    ErrorConst.INVALID_CREDENTIALS_MSG
            );
        }
    }

    public void create(User user) {
        int createResult = userMapper.create(user);

        if (createResult < 1) {
            log.error(
                    "[{}] due to failure when creating user record for: [email] [{}]",
                    ErrorConst.CREATE_RECORD_FAILED_CODE,
                    user.getEmail()
            );

            throw new TrackWizeException(
                    ErrorConst.CREATE_RECORD_FAILED_CODE,
                    ErrorConst.CREATE_RECORD_FAILED_MSG
            );
        }
    }

    public void activateUserAccount(String email) {
        int result = userMapper.updateRecordStatus(email, DBConst.STATUS_PENDING_QUERY);
        if (result < 1) {
            log.error(
                    "[{}] due to failure when updating user record status for: [email] [{}]",
                    ErrorConst.UPDATE_RECORD_FAILED_CODE,
                    email
            );

            throw new TrackWizeException(
                    ErrorConst.UPDATE_RECORD_FAILED_CODE,
                    ErrorConst.UPDATE_RECORD_FAILED_MSG
            );
        }

    }
}
