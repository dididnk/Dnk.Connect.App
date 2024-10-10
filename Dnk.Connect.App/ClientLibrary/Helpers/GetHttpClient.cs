using BaseLibrary.DTOs;

namespace ClientLibrary.Helpers
{
    public class GetHttpClient(IHttpClientFactory httpClientFactory, LocalStorageService localStorageService)
    {
        private const string HeaderKey = "Authorization";

        public async Task<HttpClient> GetPrivateHttpClient()
        {
            var client = httpClientFactory.CreateClient("SystemApiClient");

            var stringToken = await localStorageService.GetToken();
            if (string.IsNullOrEmpty(stringToken))
            {
                Console.WriteLine("Token is missing or empty.");
                return client;
            }

            var deserializeToken = Serializations.DeserializeJsonString<UserSession>(stringToken);
            if (deserializeToken != null)
            {
                Console.WriteLine($"Adding token: {deserializeToken.Token}");
                client.DefaultRequestHeaders.Authorization =
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", deserializeToken.Token);
            }

            client.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", deserializeToken.Token);

            return client;
        }

        public HttpClient GetPublicHttpClient()
        {
            var client = httpClientFactory.CreateClient("SystemApiClient");

            if (client.DefaultRequestHeaders.Contains(HeaderKey))
            {
                client.DefaultRequestHeaders.Remove(HeaderKey);
            }

            return client;
        }
    }
}

