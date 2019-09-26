using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Xunit;
using static IntegrationTest.AppServerBuilder;

namespace IntegrationTest
{
    public class FlowTest : IDisposable
    {
        private readonly HttpClient _httpClient = new HttpClient();

        private readonly AppServer _registrationServer;
        private readonly AppServer _allocationsServer;
        private readonly AppServer _backlogServer;
        private readonly AppServer _timesheetsServer;

        public FlowTest()
        {
            _registrationServer = TestAppServerBuilder()
                .AppName("RegistrationServer")
                .Port(8883)
                .Database("tracker_registration_dotnet_test")
                .SetEnvironmentVariable("EUREKA__CLIENT__SHOULDREGISTERWITHEUREKA", "false")
                .Build();

            _allocationsServer = TestAppServerBuilder()
                .AppName("AllocationsServer")
                .Port(8881)
                .Database("tracker_allocations_dotnet_test")
                .SetEnvironmentVariable("REGISTRATION_SERVER_ENDPOINT", _registrationServer.Url())
                .SetEnvironmentVariable("EUREKA__CLIENT__SHOULDFETCHREGISTRY", "false")
                .Build();

            _backlogServer = TestAppServerBuilder()
                .AppName("BacklogServer")
                .Port(8882)
                .Database("tracker_backlog_dotnet_test")
                .SetEnvironmentVariable("REGISTRATION_SERVER_ENDPOINT", _registrationServer.Url())
                .SetEnvironmentVariable("EUREKA__CLIENT__SHOULDFETCHREGISTRY", "false")
                .Build();

            _timesheetsServer = TestAppServerBuilder()
                .AppName("TimesheetsServer")
                .Port(8884)
                .Database("tracker_timesheets_dotnet_test")
                .SetEnvironmentVariable("REGISTRATION_SERVER_ENDPOINT", _registrationServer.Url())
                .SetEnvironmentVariable("EUREKA__CLIENT__SHOULDFETCHREGISTRY", "false")
                .Build();
        }

        [Fact]
        public void TestBasicFlow()
        {
            _allocationsServer.Start();
            _registrationServer.Start();
            _backlogServer.Start();
            _timesheetsServer.Start();

            HttpResponseMessage response;

            response = _httpClient.Get(_registrationServer.Url());
            Assert.Equal("Noop!", response.Content.ReadAsStringAsync().Result);

            var createdUserId = _httpClient.Post(_registrationServer.Url("/registration"), new Dictionary<string, object>
            {
                {"name", "aUser"}
            }).Content.FindId();
            AssertGreaterThan(createdUserId, 0);

            response = _httpClient.Get(_registrationServer.Url($"/users/{createdUserId}"));
            AssertNotNullOrEmpty(response.Content.ReadAsStringAsync().Result);
            Assert.True(response.IsSuccessStatusCode);

            var createdAccountId = _httpClient.Get(_registrationServer.Url($"/accounts?ownerId={createdUserId}"))
                .Content.FindId();
            AssertGreaterThan(createdAccountId, 0);

            var createdProjectId = _httpClient.Post(_registrationServer.Url("/projects"), new Dictionary<string, object>
            {
                {"accountId", createdAccountId},
                {"name", "aProject"}
            }).Content.FindId();
            AssertGreaterThan(createdProjectId, 0);

            response = _httpClient.Get(_registrationServer.Url($"/projects?accountId={createdAccountId}"));
            AssertNotNullOrEmpty(response.Content.ReadAsStringAsync().Result);
            Assert.True(response.IsSuccessStatusCode);

            response = _httpClient.Get(_allocationsServer.Url());
            Assert.Equal("Noop!", response.Content.ReadAsStringAsync().Result);

            var createdAllocationId = _httpClient.Post( _allocationsServer.Url($"/allocations?projectId={createdProjectId}"), new Dictionary<string, object>
            {
                {"projectId", createdProjectId},
                {"userId", createdUserId},
                {"firstDay", "2015-05-17"},
                {"lastDay", "2015-05-26"}
            }).Content.FindId();
            AssertGreaterThan(createdAllocationId, 0);

            response = _httpClient.Get(_allocationsServer.Url($"/allocations?projectId={createdProjectId}"));
            AssertNotNullOrEmpty(response.Content.ReadAsStringAsync().Result);
            Assert.True(response.IsSuccessStatusCode);

            response = _httpClient.Get(_backlogServer.Url());
            Assert.Equal("Noop!", response.Content.ReadAsStringAsync().Result);

            var createdStoryId = _httpClient.Post(_backlogServer.Url("/stories"), new Dictionary<string, object>
            {
                {"projectId", createdProjectId},
                {"name", "A story"}
            }).Content.FindId();
            AssertGreaterThan(createdStoryId, 0);

            response = _httpClient.Get(_backlogServer.Url($"/stories?projectId={createdProjectId}"));
            AssertNotNullOrEmpty(response.Content.ReadAsStringAsync().Result);
            AssertNotNullOrEmpty(response.Content.ReadAsStringAsync().Result);
            Assert.True(response.IsSuccessStatusCode);

            response = _httpClient.Get(_timesheetsServer.Url());
            Assert.Equal("Noop!", response.Content.ReadAsStringAsync().Result);

            var createdTimeEntryId = _httpClient.Post(_timesheetsServer.Url("/time-entries"), new Dictionary<string, object>
            {
                {"projectId", createdProjectId},
                {"userId", createdUserId},
                {"date", "2015-12-17"},
                {"hours", 8}
            }).Content.FindId();
            AssertGreaterThan(createdTimeEntryId, 0);

            response = _httpClient.Get(_timesheetsServer.Url($"/time-entries?projectId={createdProjectId}"));
            AssertNotNullOrEmpty(response.Content.ReadAsStringAsync().Result);
            Assert.True(response.IsSuccessStatusCode);
        }

        public void Dispose()
        {
            _allocationsServer.Stop();
            _backlogServer.Stop();
            _registrationServer.Stop();
            _timesheetsServer.Stop();
        }

        private static void AssertNotNullOrEmpty(string str)
        {
            Assert.NotEqual("", str);
            Assert.NotNull(str);
        }

        private static void AssertGreaterThan(long actual, long bound)
        {
            Assert.InRange(actual, bound + 1, long.MaxValue);
        }
    }

    internal static class HttpClientExtensions
    {
        internal static HttpResponseMessage Get(this HttpClient client, string url) =>
            client.GetAsync(url).Result;

        internal static HttpResponseMessage Post(this HttpClient client, string url, IDictionary<string, object> data)
        {
            var json = JsonConvert.SerializeObject(data, Formatting.Indented);
            return client.PostAsync(new Uri(url), new StringContent(json, Encoding.UTF8, "application/json")).Result;
        }
    }

    internal static class HttpContentExtensions
    {
        internal static long FindId(this HttpContent content)
        {
            var body = JToken.Parse(content.ReadAsStringAsync().Result);
            JToken id = null;

            switch (body)
            {
                case JObject _:
                    id = body.SelectToken("$.id");
                    break;
                case JArray _:
                    id = body.SelectToken("$[0].id");
                    break;
            }

            if (id == null)
            {
                Assert.True(false, $"Could not find id in response body. Response was: \n {body}");
            }

            return id.ToObject<long>();
        }
    }
}