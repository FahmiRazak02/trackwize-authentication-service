package com.trackwize.authentication.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.trackwize.authentication.model.dto.NotificationReqDTO;
import com.trackwize.common.constant.NotificationConst;
import com.trackwize.common.constant.TokenConst;
import com.trackwize.common.util.ActiveMQUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class NotificationService {

    @Value("${spring.artemis.queues.email}")
    private String emailQueue;

    private final ActiveMQUtil activeMQUtil;

    /**
     * Send email notification by pushing message to ActiveMQ email queue.
     *
     * @param reqDTO The notification request data transfer object containing email details.
     * @throws JsonProcessingException If there is an error during JSON processing.
     */
    public void sendEmail(NotificationReqDTO reqDTO) throws JsonProcessingException {
        String correlationId = reqDTO.getTrackingId();

        ObjectMapper objectMapper = new ObjectMapper();
        String messageReq = objectMapper.writeValueAsString(reqDTO);

        activeMQUtil.send(correlationId, emailQueue, messageReq);
    }

    public void sendPasswordResetEmail(String email, String token, String trackingId) throws JsonProcessingException {
//        1. Build the email request payload and attach tracking ID
        var reqDTO = buildPasswordResetReqDTO(email, token);
        reqDTO.setTrackingId(trackingId);

//        2. Send reset password email
        sendEmail(reqDTO);
    }

    /**
     * Build the email request DTO for password reset.
     *
     * @param email The recipient email address.
     * @param token The password reset token.
     * @return The constructed NotificationReqDTO.
     */
    private NotificationReqDTO buildPasswordResetReqDTO(String email, String token) {
        var reqDTO = new NotificationReqDTO();
        reqDTO.setNotificationType(NotificationConst.EMAIL_NTF_TYPE);
        reqDTO.setTemplate(NotificationConst.PASSWORD_RESET_TEMPLATE);
        reqDTO.setRecipient(email);
        reqDTO.setSubject("TrackWize Password Reset Request");

        Map<String, Object> contents = new HashMap<>();
        contents.put("title", "TrackWize Password Reset Request");
        contents.put("message", "Click the link below to reset your password:");
        contents.put("token", token);
        contents.put("expiry", TokenConst.RESET_PASSWORD_TOKEN_EXPIRY);

        reqDTO.setContents(contents);
        return reqDTO;
    }

    public void sendAccountIsCreatedEmail(String email, String name, String trackingId) throws JsonProcessingException {
        var reqDTO = buildAccountIsCreatedReqDTO(email, name);
        reqDTO.setTrackingId(trackingId);

        sendEmail(reqDTO);
    }

    private NotificationReqDTO buildAccountIsCreatedReqDTO(String email, String name) {
        var reqDTO = new NotificationReqDTO();
        reqDTO.setNotificationType(NotificationConst.EMAIL_NTF_TYPE);
        reqDTO.setTemplate(NotificationConst.ACCOUNT_IS_CREATED_TEMPLATE);
        reqDTO.setRecipient(email);
        reqDTO.setSubject("Trackwize Account");

        Map<String, Object> contents = new HashMap<>();
        contents.put("Title", "Trackwize Account is Successfully Created, Welcome Onboard!");
        contents.put("message", "Your Trackwize Account is Created Successfully");
        contents.put("name", name);

        reqDTO.setContents(contents);
        return reqDTO;
    }

    public void sendAccountIsVerifiedEmail(String email, String name, String token, String trackingId) throws JsonProcessingException {
        var reqDTO = buildAccountIsVerifiedReqDTO(email, name, token);
        reqDTO.setTrackingId(trackingId);

        sendEmail(reqDTO);
    }

    private NotificationReqDTO buildAccountIsVerifiedReqDTO(String email, String name, String token) {
        var reqDTO = new NotificationReqDTO();
        reqDTO.setNotificationType(NotificationConst.EMAIL_NTF_TYPE);
        reqDTO.setTemplate(NotificationConst.ACCOUNT_IS_VERIFIED_TEMPLATE);
        reqDTO.setRecipient(email);
        reqDTO.setSubject("Trackwize Account");

        Map<String, Object> contents = new HashMap<>();
        contents.put("Title", "Trackwize Account Verification");
        contents.put("message", "Please Verify Your Account");
        contents.put("name", name);
        contents.put("token", token);
        contents.put("expiry", TokenConst.ACCOUNT_VERIFICATION_TOKEN_EXPIRY);

        reqDTO.setContents(contents);
        return reqDTO;
    }

    public void sendAccountIsActivateEmail(String email, String trackingId) throws JsonProcessingException {
        var reqDTO = buildAccountIsActivateReqDTO(email);
        reqDTO.setTrackingId(trackingId);

        sendEmail(reqDTO);
    }

    private NotificationReqDTO buildAccountIsActivateReqDTO(String email) {
        var reqDTO = new NotificationReqDTO();
        reqDTO.setNotificationType(NotificationConst.EMAIL_NTF_TYPE);
        reqDTO.setTemplate(NotificationConst.ACCOUNT_IS_ACTIVATE_TEMPLATE);
        reqDTO.setRecipient(email);
        reqDTO.setSubject("Trackwize Account is Activate");

        Map<String, Object> contents = new HashMap<>();
        contents.put("Title", "Trackwize Account Activate");
        contents.put("message", "Your Are Ready to Roll!");

        reqDTO.setContents(contents);
        return reqDTO;
    }
}
