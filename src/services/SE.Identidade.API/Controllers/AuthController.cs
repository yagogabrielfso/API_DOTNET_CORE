using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SE.Identidade.API.Models;

namespace SE.Identidade.API.Controllers
{
    [ApiController]
    [Route("api/identidade")]
    public class AuthController : Controller
    {
        //Dependency Injection 
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
               
        public AuthController(SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager)
        {
            _signInManager = signInManager;
            _userManager = userManager;
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

    }
}
