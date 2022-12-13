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
        //M�todo assincrono que retorna uma task de action result
        public async Task <ActionResult> Registrar (UsuarioRegistro usuarioRegistro)
        {
            // Validar se a model que recebemos est� OK
            if (!ModelState.IsValid) return BadRequest();

            // a inst�ncia do user n�o requer senha, pois ser� criptografada.
            var user = new IdentityUser
            {
                UserName = usuarioRegistro.Email,
                Email = usuarioRegistro.Email,
                EmailConfirmed = true

            };

            // Com o sign manager e o usermanager na m�o
            // com a linha abaixo � criado de forma ass�ncrona um usu�rio, passando user, e a senha criptografada.
            var result = await _userManager.CreateAsync(user, usuarioRegistro.Senha);

            // Na minha abaixo confirma que deu tudo certo na cria��o do usu�rio e poder� tomar a proxima a��o
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
