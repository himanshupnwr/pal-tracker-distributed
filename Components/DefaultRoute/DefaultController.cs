using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DefaultRoute
{
    [Route("")]
    public class DefaultController : ControllerBase
    {
        [HttpGet]
        public string Default() => "Noop!";
    }
}