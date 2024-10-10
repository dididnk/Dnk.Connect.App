﻿using BaseLibrary.DTOs;
using Microsoft.AspNetCore.Components.Authorization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace ClientLibrary.Helpers
{
    public class CustomAuthenticationStateProvider(LocalStorageService localStorageService) : AuthenticationStateProvider
    {
        private readonly ClaimsPrincipal anonymous = new(new ClaimsIdentity());

        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            var stringToken = await localStorageService.GetToken();
            if (string.IsNullOrEmpty(stringToken)) return await Task.FromResult(new AuthenticationState(anonymous));

            var deserializeToken = Serializations.DeserializeJsonString<UserSession>(stringToken);
            if (deserializeToken == null || string.IsNullOrEmpty(deserializeToken.Token))
                return await Task.FromResult(new AuthenticationState(anonymous));

            var getUserClaims = DecryptToken(deserializeToken.Token);
            if (getUserClaims == null) return await Task.FromResult(new AuthenticationState(anonymous));

            var claimPrincipal = SetClaimPrincipal(getUserClaims);
            return await Task.FromResult(new AuthenticationState(claimPrincipal));
        }


        private ClaimsPrincipal SetClaimPrincipal(CustomUserClaims claims)
        {
            if (claims.Email is null) return new ClaimsPrincipal();

            var _claims = new List<Claim>
            {
                new(ClaimTypes.NameIdentifier, claims.Id!),
                new(ClaimTypes.Name, claims.Name!),
                new(ClaimTypes.Email, claims.Email!),
                new(ClaimTypes.Role, claims.Role!),
            };

            return new ClaimsPrincipal(new ClaimsIdentity(_claims, "JwtAuth"));
        }

        private static CustomUserClaims DecryptToken(string jwtToken)
        {
            if (string.IsNullOrEmpty(jwtToken)) return new CustomUserClaims();

            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(jwtToken);

            var userId = token.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier);
            var name = token.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Name);
            var email = token.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Email);
            var role = token.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Role);

            return new CustomUserClaims(userId!.Value!, name!.Value!, email!.Value!, role!.Value!);
        }

        public async Task UpdateAthenticationState(UserSession userSession)
        {
            var claimsPrincipal = new ClaimsPrincipal();
            if (userSession.Token != null || userSession.RefreshToken != null)
            {
                var serializerSession = Serializations.SerializeObj(userSession);
                await localStorageService.SetToken(serializerSession);
                var getUserClaims = DecryptToken(userSession.Token);
                claimsPrincipal = SetClaimPrincipal(getUserClaims);
            }
            else
            {
                await localStorageService.RemoveToken();
            }
            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(claimsPrincipal)));
        }
    }
}
