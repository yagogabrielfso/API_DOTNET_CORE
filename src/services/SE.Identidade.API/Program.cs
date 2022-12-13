using Microsoft.EntityFrameworkCore;
using SE.Identidade.API.Data;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Hosting;
using Microsoft.OpenApi.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using SE.Identidade.API.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.


builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));





builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddDefaultIdentity<IdentityUser>()
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddSwaggerGen(option =>
{
    option.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Enterprise Identity API",
        Contact = new OpenApiContact() { Name = "Yago Gabriel", Email = "gabriel_oliveirafs@hotmail.com" }

    });
});

var appSettingsSection = builder.Configuration.GetSection("AppSettings"); // Vá até o arquivo de configuração e pegue o app settings
builder.Services.Configure<AppSettings>(appSettingsSection); // Configure o middleware (pipeline) pra que a classe AppSettings represente os dados da seção appsettings section

var appSettings = appSettingsSection.Get<AppSettings>(); // declaração appsettings através da section vai obter a classe AppSettings ja populada
var key = Encoding.ASCII.GetBytes(appSettings.Secret);   // essa chave vai ser transformada numa sequencia de bytes no formado ASCII pra que ela seja usada numa SymmetricSecurityKey




// Adicionando como option de autenticação o Jason Web Token.
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(bearerOptions => // Adicionando suporte pra esse tipo de token com algumas opções.
{
    bearerOptions.RequireHttpsMetadata = true;   // Requer acesso pelo https
    bearerOptions.SaveToken = true;              // Token guardado na instância quando realizar login
    bearerOptions.TokenValidationParameters = new TokenValidationParameters
    {
        // Parâmetros de validação do token
        ValidateIssuerSigningKey = true,    // Audiência é a onde o token pode ser utilizado... nessa linha valido o emissor com base na assinatura 
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("x")), // a partir dessa classe trazemos uma sequencia de bytes onde a chave vai estar no parâmetro
        ValidateIssuer = true, // VAlidar o issuer seja válido para que o token seja válido apenas DENTRO das APIS que eu quiser
        ValidateAudience = true, // Pra quais dominios esse token é válido, 
        ValidAudience = appSettings.ValidoEm, // criamos a audiência válida.
        ValidIssuer = appSettings.Emissor   // Criamos um issuer válido, configuramos os dados de emissor do token 
         
    };


});







var app = builder.Build();  


// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseSwagger();
    app.UseSwaggerUI(option =>
    {
        option.SwaggerEndpoint("/swagger/v1/swagger.json", "v1");
        
    });
}


app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();


app.MapControllers();

app.Run();
