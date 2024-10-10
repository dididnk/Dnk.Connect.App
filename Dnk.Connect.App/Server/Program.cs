using Microsoft.EntityFrameworkCore;
using ServerLibrary.Data;
using ServerLibrary.Helpers;
using ServerLibrary.Repositories.Contracts;
using ServerLibrary.Repositories.Implementations;

var builder = WebApplication.CreateBuilder(args);

// Ajout des services au conteneur
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Configuration JWT
builder.Services.Configure<JwtSection>(builder.Configuration.GetSection("JwtSection"));
builder.Services.AddScoped<IUserAccount, UserAccountRepository>();
var jwtSection = builder.Configuration.GetSection(nameof(JwtSection)).Get<JwtSection>();

// Configuration du DbContext
builder.Services.AddDbContext<AppDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection") ??
        throw new InvalidOperationException("Sorry, your connection is not found!"));
});

// Configuration JWT
builder.Services.Configure<JwtSection>(builder.Configuration.GetSection("JwtSection"));
builder.Services.AddScoped<IUserAccount, UserAccountRepository>();

// Configuration CORS pour autoriser le client Blazor
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowBlazorWasm",
        policyBuilder => policyBuilder
            .WithOrigins("http://localhost:5165", "https://localhost:7000")
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials()); // Transmettre des cookies ou tokens
});

var app = builder.Build();

// Configuration du pipeline des requêtes HTTP
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// Appliquer CORS avant les autres middlewares
app.UseCors("AllowBlazorWasm");

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
