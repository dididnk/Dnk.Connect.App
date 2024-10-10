using BaseLibrary.DTOs;
using ClientLibrary.Helpers;

namespace Client.Pages.AccountPages
{
    public partial class LoginPage
    {
        public Login User = new();

        public async Task HandleLogin()
        {
            var result = await AccountService.SignInAsync(User);
            if (result.Flag)
            {
                var customAthStateProvider = (CustomAuthenticationStateProvider)AuthStateProvider;

                await customAthStateProvider.UpdateAthenticationState(new UserSession()
                {
                    Token = result.Token,
                    RefreshToken = result.RefreshToken,
                });

                NavManager.NavigateTo("/", forceLoad: true);
            }
        }
    }
}
