using BaseLibrary.DTOs;

namespace Client.Pages.AccountPages
{
    public partial class RegisterPage
    {
        public Register User = new();

        public async Task HandleRegistration()
        {
            var result = await AccountService.CreateAsync(User);
            if (result.Flag)
            {
                NavManager.NavigateTo("/identity/account/login", forceLoad: true);
            }
        }
    }
}
