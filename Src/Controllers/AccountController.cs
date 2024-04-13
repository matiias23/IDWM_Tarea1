using courses_dotnet_api.Src.DTOs.Account;
using courses_dotnet_api.Src.Interfaces;
using Microsoft.AspNetCore.Mvc;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace courses_dotnet_api.Src.Controllers;

public class AccountController : BaseApiController
{
    private readonly IUserRepository _userRepository;
    private readonly IAccountRepository _accountRepository;

    public AccountController(IUserRepository userRepository, IAccountRepository accountRepository)
    {
        _userRepository = userRepository;
        _accountRepository = accountRepository;
    }

    [HttpPost("register")]
    public async Task<IResult> Register(RegisterDto registerDto)
    {
        if (
            await _userRepository.UserExistsByEmailAsync(registerDto.Email)
            || await _userRepository.UserExistsByRutAsync(registerDto.Rut)
        )
        {
            return TypedResults.BadRequest("User already exists");
        }

        await _accountRepository.AddAccountAsync(registerDto);

        if (!await _accountRepository.SaveChangesAsync())
        {
            return TypedResults.BadRequest("Failed to save user");
        }

        AccountDto? accountDto = await _accountRepository.GetAccountAsync(registerDto.Email);

        return TypedResults.Ok(accountDto);
    }

    [HttpPost("login")]
    [Route("api/account/login")]
    public async Task<ActionResult<AccountDto>> Login(LoginDto loginDto)
    {
    
        var user = await _accountRepository.GetUserByEmailAsync(loginDto.Email);
        
        //aca verificamos si el usuario existe en el sistema
        if (user == null)
            return Unauthorized("Las credenciales de acceso son incorrectas o el usuario no está registrado en el sistema");
        
        //genera el hash de contraseña y compara con el hash almacenado
        using var hmac = new HMACSHA512(user.PasswordSalt);
        var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

        for (int i = 0; i < computedHash.Length; i++)
        {
            if (computedHash[i] != user.PasswordHash[i])
            {
                return Unauthorized("Las credenciales de acceso son incorrectas o el usuario no está registrado en el sistema");
            }
        }

        //obtiene los datos del usuario para devolverlas en la respuesta
        AccountDto? accountDto = await _accountRepository.GetAccountAsync(loginDto.Email);

        return Ok(accountDto);

    }
}
