using FluentValidation;
using SafeVault.Api.Dtos;

namespace SafeVault.Api.Validation
{
    public class RegisterRequestValidator : AbstractValidator<RegisterRequest>
    {
        public RegisterRequestValidator()
        {
            RuleFor(x => x.Email).NotEmpty().EmailAddress();
            RuleFor(x => x.Password).NotEmpty().MinimumLength(8).MaximumLength(128);
            RuleFor(x => x.Role).Must(r => r == null || r is "User" or "Admin");
        }
    }
}
