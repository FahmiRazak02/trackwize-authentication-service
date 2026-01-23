package com.trackwize.authentication.model.dto;

import com.trackwize.common.validation.PasswordValidator;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@PasswordValidator
@NoArgsConstructor
@AllArgsConstructor
public class PasswordResetProcessReqDTO {

    @NotBlank(message = "password is required")
    private String password;

    @NotBlank(message = "confirm password is required")
    private String confirmPassword;
}
