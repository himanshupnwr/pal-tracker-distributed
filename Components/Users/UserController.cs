using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Users
{
    [Route("users"), Produces("application/json")]
    public class UserController : ControllerBase
    {
        private readonly IUserDataGateway _gateway;

        public UserController(IUserDataGateway gateway)
        {
            _gateway = gateway;
        }

        [HttpGet("{id}")]
        public IActionResult Get(int id)
        {
            var record = _gateway.FindObjectBy(id);

            if (record == null)
            {
                return NotFound();
            }

            return Ok(new UserInfo(record.Id, record.Name, "user info"));
        }
    }
}