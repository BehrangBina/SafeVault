using FluentValidation;
using SafeVault.Api.Dtos;

namespace SafeVault.Api.Validation
{
    public class VaultItemCreateValidator : AbstractValidator<VaultItemCreate>
    {
        public VaultItemCreateValidator()
        {
            RuleFor(x => x.Content).NotEmpty().MaximumLength(5000);
        }
    }
}
