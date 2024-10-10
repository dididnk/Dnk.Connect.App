using BaseLibrary.DTOs;
using ClientLibrary.Helpers;

namespace Client.Layout
{
    public partial class MainLayout
    {
        public async Task LogOutClicked()
        {
            var logoutModel = new UserSession();
            var customAuthStateProvider = (CustomAuthenticationStateProvider)AuthStateProvider;

            await customAuthStateProvider.UpdateAthenticationState(logoutModel);

            NavManager.NavigateTo("/", forceLoad: true);
        }
    }
}
