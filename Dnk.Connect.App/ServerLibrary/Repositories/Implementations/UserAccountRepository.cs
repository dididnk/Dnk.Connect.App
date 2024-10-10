using BaseLibrary.DTOs;
using BaseLibrary.Entities;
using BaseLibrary.Responses;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using ServerLibrary.Data;
using ServerLibrary.Helpers;
using ServerLibrary.Repositories.Contracts;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Constants = ServerLibrary.Helpers.Constants;

namespace ServerLibrary.Repositories.Implementations
{
    public class UserAccountRepository : IUserAccount
    {
        private readonly IOptions<JwtSection> _jwtConfig;
        private readonly AppDbContext _dbContext;

        public UserAccountRepository(IOptions<JwtSection> config, AppDbContext appDbContext)
        {
            _jwtConfig = config;
            _dbContext = appDbContext;
        }
        public async Task<GeneralResponse> CreateAsync(Register user)
        {
            if (user is null) return new GeneralResponse(false, "Model is empty !");

            var checkUser = await FindByUserEmail(user.Email);
            if (checkUser != null) return new GeneralResponse(false, "User registred already !");

            // Save user
            var applicationUser = await AddToDatabaseAsync(new ApplicationUser()
            {
                Fullname = user.Fullname,
                Email = user.Email,
                Password = BCrypt.Net.BCrypt.HashPassword(user.Password)
            });

            // Check, create and assign user role : Admin
            var checkAdminRole = await _dbContext.SystemRoles.FirstOrDefaultAsync(x => x.Name!.Equals(Constants.Admin));
            if (checkAdminRole is null)
            {
                var createAdminRole = await AddToDatabaseAsync(new SystemRole()
                {
                    Name = Constants.Admin
                });
                await AddToDatabaseAsync(new UserRole()
                {
                    RoleId = createAdminRole.Id,
                    UserId = applicationUser.Id,
                });
                return new GeneralResponse(true, "Account created !");
            }

            // Check, create and assign user role : User
            var checkUserRole = await _dbContext.SystemRoles.FirstOrDefaultAsync(x => x.Name!.Equals(Constants.User));
            SystemRole response = new();
            if (checkUserRole is null)
            {
                response = await AddToDatabaseAsync(new SystemRole()
                {
                    Name = Constants.User
                });
            }
            else
            {
                await AddToDatabaseAsync(new UserRole()
                {
                    RoleId = checkUserRole.Id,
                    UserId = applicationUser.Id,
                });
            }

            return new GeneralResponse(true, "Account created !");
        }

        private async Task<T> AddToDatabaseAsync<T>(T model)
        {
            var result = _dbContext.Add(model!);
            await _dbContext.SaveChangesAsync();
            return (T)result.Entity;
        }

        private async Task<ApplicationUser> FindByUserEmail(string? email)
        {
            return await _dbContext.ApplicationUsers.FirstOrDefaultAsync(x => x.Email!.ToLower().Equals(email!.ToLower()));
        }

        public async Task<LoginResponse> SignInAsync(Login user)
        {
            if (user is null) return new LoginResponse(false, "Model is empty !");
            var applicationUser = await FindByUserEmail(user.Email);
            if (applicationUser is null) return new LoginResponse(false, "User not found");

            // Verify password
            if (!BCrypt.Net.BCrypt.Verify(user.Password, applicationUser.Password))
            {
                return new LoginResponse(false, "Email or Password not valid");
            }
            var getUserRole = await FindUserRole(applicationUser.Id);
            if (getUserRole is null) return new LoginResponse(false, "User not found");

            var getRoleName = await FindRoleName(getUserRole.UserId);
            if (getRoleName is null) return new LoginResponse(false, "User role not found");

            string jwtToken = GenerateToken(applicationUser, getRoleName!.Name);
            string refreshToken = GenerateRefreshToken();

            // Save the Refresh token to the database
            var findUser = await _dbContext.RefreshTokenInfos.FirstOrDefaultAsync(x => x.UserId == applicationUser.Id);

            if (findUser is not null)
            {
                findUser!.Token = refreshToken;
                await _dbContext.SaveChangesAsync();
            }
            else
            {
                await AddToDatabaseAsync(new RefreshTokenInfo()
                {
                    Token = refreshToken,
                    UserId = applicationUser.Id,
                });
            }

            return new LoginResponse(true, "Login successfully", jwtToken, refreshToken);
        }

        private async Task<SystemRole?> FindRoleName(int roleId)
        {
            return await _dbContext.SystemRoles.FirstOrDefaultAsync(x => x.Id == roleId);
        }

        private async Task<UserRole?> FindUserRole(int userId)
        {
            return await _dbContext.UserRoles.FirstOrDefaultAsync(x => x.UserId == userId);
        }

        private static string GenerateRefreshToken()
        {
            return Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        }

        private string GenerateToken(ApplicationUser user, string role)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtConfig.Value.Key!));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var userClaims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Fullname!),
                new Claim(ClaimTypes.Email, user.Email!),
                new Claim(ClaimTypes.Role, role!),
            };
            var token = new JwtSecurityToken
            (
                issuer: _jwtConfig.Value.Issuer,
                audience: _jwtConfig.Value.Audience,
                claims: userClaims,
                expires: DateTime.Now.AddSeconds(2),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public async Task<LoginResponse> RefreshTokenAsync(RefreshToken token)
        {
            if (token is null) return new LoginResponse(false, "Model is empty");

            var findToken = await _dbContext.RefreshTokenInfos.FirstOrDefaultAsync(x => x!.Token!.Equals(token.Token));
            if (findToken is null) return new LoginResponse(false, "Refresh token is required");

            // get user details
            var user = await _dbContext.ApplicationUsers.FirstOrDefaultAsync(x => x.Id == findToken.UserId);
            if (user is null) return new LoginResponse(false, "Refresh token could not be generated because user not found");

            var userRole = await FindUserRole(user.Id);
            var roleName = await FindRoleName(userRole!.RoleId);
            var jwtTokrn = GenerateToken(user, roleName!.Name!);
            string refreshToken = GenerateRefreshToken();

            var updateRefreshToken = await _dbContext.RefreshTokenInfos.FirstOrDefaultAsync(x => x.UserId == user.Id);
            if (updateRefreshToken is null) return new LoginResponse(false, "Refresh token could not be generated because user has not signed in");

            updateRefreshToken.Token = refreshToken;
            await _dbContext.SaveChangesAsync();

            return new LoginResponse(true, "Token refreshed sucessfully", jwtTokrn, refreshToken);
        }
    }
}
