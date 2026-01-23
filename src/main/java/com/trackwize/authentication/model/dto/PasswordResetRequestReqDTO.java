package com.trackwize.authentication.model.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class PasswordResetRequestReqDTO {

    @NotBlank(message = "email is required")
    @Email(message = "invalid email format")
    private String email;
}
