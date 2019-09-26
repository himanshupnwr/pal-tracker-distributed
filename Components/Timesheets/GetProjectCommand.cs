using System;
using System.Threading.Tasks;
using Steeltoe.CircuitBreaker.Hystrix;

namespace Timesheets
{
    public class GetProjectCommand : HystrixCommand<ProjectInfo>
    {
        private readonly Func<long, Task<ProjectInfo>> _getProjectFn;
        private readonly long _projectId;
        private readonly Func<long, Task<ProjectInfo>> _getProjectFallbackFn;

        public GetProjectCommand(
            Func<long, Task<ProjectInfo>> getProjectFn,
            Func<long, Task<ProjectInfo>> getProjectFallbackFn,
            long projectId
        ) : base(HystrixCommandGroupKeyDefault.AsKey("ProjectClientGroup"))
        {
            _getProjectFn = getProjectFn;
            _projectId = projectId;
            _getProjectFallbackFn = getProjectFallbackFn;
        }

        protected override async Task<ProjectInfo> RunAsync() => await _getProjectFn(_projectId);
        protected override async Task<ProjectInfo> RunFallbackAsync() => await _getProjectFallbackFn(_projectId);
    }
}