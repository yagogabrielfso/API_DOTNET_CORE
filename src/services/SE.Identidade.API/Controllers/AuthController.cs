using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using SE.Identidade.API.Extensions;
using SE.Identidade.API.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace SE.Identidade.API.Controllers
{
    [ApiController]
    [Route("api/identidade")]
    public class AuthController : Controller
    {
        //Dependency Injection 
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly AppSettings _appSettings;
               
        public AuthController(SignInManager<IdentityUser> signInManager,
                              UserManager<IdentityUser> userManager, 
                              IOptions<AppSettings> appSettings)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _appSettings = appSettings.Value;
        }

        [HttpPost("nova-conta")]
        //Método assincrono que retorna uma task de action result
        public async Task <ActionResult> Registrar (UsuarioRegistro usuarioRegistro)
        {
            // Validar se a model que recebemos está OK
            if (!ModelState.IsValid) return BadRequest();

            // a instância do user não requer senha, pois será criptografada.
            var user = new IdentityUser
            {
                UserName = usuarioRegistro.Email,
                Email = usuarioRegistro.Email,
                EmailConfirmed = true

            };

            // Com o sign manager e o usermanager na mão
            // com a linha abaixo é criado de forma assíncrona um usuário, passando user, e a senha criptografada.
            var result = await _userManager.CreateAsync(user, usuarioRegistro.Senha);

            // Na minha abaixo confirma que deu tudo certo na criação do usuário e poderá tomar a proxima ação
            if(result.Succeeded)
            {

                await _signInManager.SignInAsync(user, isPersistent: false);
                return Ok();
            }
            
            return BadRequest();


        }
        [HttpPost("autenticar")]
        public async Task<ActionResult> Login(UsuarioLogin usuarioLogin)
        {
            if (!ModelState.IsValid) return BadRequest();

            var result = await _signInManager.PasswordSignInAsync(usuarioLogin.Email, usuarioLogin.Senha, false, true);

            if (result.Succeeded)
            {
                return Ok();
            }

            return BadRequest();

        }


        private async Task<UsuarioRespostaLogin> GerarJwt(string email)
        {
            var user = await _userManager.FindByEmailAsync(email); // Obter usuário através do UserManger.FindByEmailAsync
            var claims = await _userManager.GetClaimsAsync(user);
            var userRoles = await _userManager.GetRolesAsync(user);

            claims.Add(new Claim(JwtRegisteredClaimNames.Sub, user.Id));
            claims.Add(new Claim(JwtRegisteredClaimNames.Email, user.Email));
            claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())); // ID UNICO DO TOKEN
            claims.Add(new Claim(JwtRegisteredClaimNames.Nbf, ToUnixEpochDate(DateTime.UtcNow).ToString())); // QUANDO O TOKEN VAI EXPIRAR
            claims.Add(new Claim(JwtRegisteredClaimNames.Iat, ToUnixEpochDate(DateTime.UtcNow).ToString(), ClaimValueTypes.Integer64)); // QUANDO FOI EMITIDO

            foreach(var userRole in userRoles)
            {
                claims.Add(new Claim("role", userRole));
            }

            var identityClaims = new ClaimsIdentity();
            identityClaims.AddClaims(claims);

            var tokenHandler = new JwtSecurityTokenHandler(); // com base na chave que eu tenho, irá gerar o token, (precisa da dependecy injection de appsettings)
            var key = Encoding.ASCII.GetBytes(_appSettings.Secret));

            var token = tokenHandler.CreateToken(new SecurityTokenDescriptor
            {
                
                Issuer = _appSettings.Emissor,
                Audience = _appSettings.ValidoEm,
                Subject = identityClaims,
                Expires = DateTime.UtcNow.AddHours(_appSettings.ExpiracaoHoras),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)


            });

        }

        private static long ToUnixEpochDate(DateTime date)
        => (long)Math.Round((date.ToUniversalTime() - new DateTimeOffset(1970, 1, 1, 0, 0, 0, 0, TimeSpan.Zero)).TotalSeconds);

    }
}
