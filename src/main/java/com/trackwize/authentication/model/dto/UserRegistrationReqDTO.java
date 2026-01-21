package com.trackwize.authentication.model.dto;

import com.trackwize.common.constant.CommonConst;
import com.trackwize.common.validation.PasswordValidator;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@PasswordValidator
@NoArgsConstructor
@AllArgsConstructor
public class UserRegistrationReqDTO {

    @NotBlank(message = "email is required")
    @Email(message = "invalid email format")
    private String email;

    @NotBlank(message = "password is required")
    private String password;

    @NotBlank(message = "confirm password is required")
    private String confirmPassword;

    @NotBlank(message = "contact no is required")
    @Pattern(regexp = CommonConst.CONTACT_NO_REGEX, message = "contact no must be valid")
    private String contactNumber;

    @NotBlank(message = "name is required")
    @Size(max = 255, message = "email must not exceed 255 characters")
    private String name;
}
