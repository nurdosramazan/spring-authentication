package kz.nurdos.spring_security.dto.authentication;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.hibernate.validator.constraints.Length;

public class UserRegistrationRequest {
    @NotBlank(message = "Username is blank")
    @Size(min = 2, max = 20, message = "Username must be 2 to 20 characters")
    @Pattern(regexp = "^[a-zA-Z0-9._]+$", message = "Invalid symbols in username")
    private final String username;

    @NotNull(message = "Password is not provided")
    @Length(min = 8, message = "Password must have at least 8 characters")
    private final String password;

    @NotBlank(message = "First name is blank")
    @Length(min = 2, max = 20, message = "First name must be 2 to 20 characters")
    @Pattern(regexp = "^\\p{L}+(?:[-']\\p{L}+)?$", message = "First name contains invalid characters")
    private final String firstName;

    @NotBlank(message = "Last name is blank")
    @Length(min = 2, max = 20, message = "Last name must be 2 to 20 characters")
    @Pattern(regexp = "^\\p{L}+(?:[-']\\p{L}+)?$", message = "Last name contains invalid characters")
    private final String lastName;

    @NotBlank(message = "Email is blank")
    @Email(message = "Invalid email format")
    private final String email;

    public UserRegistrationRequest(String username, String password, String firstName, String lastName, String email) {
        this.username = username;
        this.password = password;
        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getFirstName() {
        return firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public String getEmail() {
        return email;
    }
}
