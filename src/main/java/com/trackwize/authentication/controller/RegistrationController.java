package com.trackwize.authentication.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.trackwize.authentication.model.dto.UserRegistrationReqDTO;
import com.trackwize.authentication.service.RegistrationService;
import com.trackwize.common.util.ResponseUtil;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/v1/reg")
@RequiredArgsConstructor
public class RegistrationController {

    private final RegistrationService registrationService;

    @PostMapping("/submit")
    public ResponseUtil submitUserRegistration(
            @ModelAttribute("trackingId") String trackingId,
            @RequestBody @Valid UserRegistrationReqDTO reqDTO
    ) throws JsonProcessingException {
        ResponseUtil responseUtil = ResponseUtil.success();

        registrationService.submitUserRegistration(reqDTO,trackingId);

        responseUtil.setMsg("User Account is Created, Please Check your email for verification link.");
        return responseUtil;
    }

    @PostMapping("/verify-account")
    public ResponseUtil verifyUserAccount(
            @ModelAttribute("trackingId") String trackingId,
            @RequestParam String token
    ) throws JsonProcessingException {
        ResponseUtil responseUtil = ResponseUtil.success();

        registrationService.verifyAccount(token, trackingId);

        responseUtil.setMsg("User Account is Verified, Enjoy!");
        return responseUtil;
    }
}
