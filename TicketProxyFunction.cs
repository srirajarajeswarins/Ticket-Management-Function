using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
// This function acts as a proxy to the Ticket API, 
//forwarding incoming HTTP requests while attaching a valid JWT token for authentication.
namespace TicketManagementFunction
{
    public class TicketProxyFunction
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ILogger<TicketProxyFunction> _logger;
        private readonly string _ticketApiBaseUrl;
        private readonly string _apiUsername;
        private readonly string _apiPassword;

        // Token cache (access + refresh)
        private static string? _cachedToken;
        private static DateTime _tokenExpiry = DateTime.MinValue;
        private static string? _cachedRefreshToken;
        private static DateTime _refreshTokenExpiry = DateTime.MinValue;
        private static readonly object _tokenLock = new();
        private const int AccessTokenSkewSeconds = 10;
        
        public TicketProxyFunction(IHttpClientFactory httpClientFactory, ILogger<TicketProxyFunction> logger)
        {
            _httpClientFactory = httpClientFactory;
            _logger = logger;
            _ticketApiBaseUrl = Environment.GetEnvironmentVariable("TicketApiBaseUrl") ?? "http://localhost:5000";
            _apiUsername = Environment.GetEnvironmentVariable("ApiUsername") ?? "admin";
            _apiPassword = Environment.GetEnvironmentVariable("ApiPassword") ?? "admin123";
        }

        /// This method first checks if there is a cached access token that is still valid (not expired).
        /// returns the cached token if it is valid. If the cached token is missing or expired, it attempts to refresh the token using a valid refresh token.
        /// If the refresh is successful, it returns the new access token. If the refresh fails (e.g., invalid/expired refresh token), it falls back to performing a login with the configured API credentials to obtain a new access token and refresh token.
        private async Task<string?> GetTokenAsync(HttpClient client)
        {
            lock (_tokenLock)
            {
                // Return cached access token if it exists and still valid.
                if (!string.IsNullOrEmpty(_cachedToken) && _tokenExpiry > DateTime.UtcNow.AddSeconds(AccessTokenSkewSeconds))
                {
                    _logger.LogInformation("Using cached access token");
                    return _cachedToken;
                }
            }

            // Otherwise, try to refresh the token if we have a valid refresh token.
            if (await TryRefreshTokenAsync(client))
            {
                return _cachedToken;
            }

            // If refresh fails or missing: fall back to username/password login.
            return await LoginAndCacheAsync(client);
        }
        // This method checks if there is a valid refresh token available in the cache.
        //returns true only if a refresh token exists and has not expired.
        private bool HasValidRefreshToken()
        {
            lock (_tokenLock)
            {
                return !string.IsNullOrEmpty(_cachedRefreshToken) && _refreshTokenExpiry > DateTime.UtcNow;
            }
        }
        // This method attempts to refresh the access token using the cached refresh token. 
        // If successful, it updates the cached access and refresh tokens along with their expiration times. 
        // It returns true if the refresh was successful, or false if it failed (e.g., invalid/expired refresh token or API error).
        private async Task<bool> TryRefreshTokenAsync(HttpClient client)
        {
            if (!HasValidRefreshToken())
            {
                return false;
            }

            string refreshToken;
            lock (_tokenLock)
            {
                refreshToken = _cachedRefreshToken!;
            }

            _logger.LogInformation("Refreshing access token using refresh token");

            try
            {
                var refreshUrl = $"{_ticketApiBaseUrl}/api/Auth/refresh";
                var refreshRequest = new { refreshToken };
                var jsonContent = JsonSerializer.Serialize(refreshRequest);
                var content = new StringContent(jsonContent, Encoding.UTF8, "application/json");

                var response = await client.PostAsync(refreshUrl, content);
                if (!response.IsSuccessStatusCode)
                {
                    return false;
                }

                var responseContent = await response.Content.ReadAsStringAsync();
                var loginResponse = JsonSerializer.Deserialize<LoginResponse>(responseContent, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

                if (loginResponse?.Token == null || string.IsNullOrEmpty(loginResponse.RefreshToken))
                {
                    return false;
                }

                lock (_tokenLock)
                {
                    // Refresh returns a new access token and rotates the refresh token.
                    _cachedToken = loginResponse.Token;
                    _tokenExpiry = loginResponse.ExpiresAt;
                    _cachedRefreshToken = loginResponse.RefreshToken;
                    _refreshTokenExpiry = loginResponse.RefreshExpiresAt;
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while refreshing access token");
                return false;
            }
        }
        // This method performs a login using the configured API credentials to 
        // obtain a new access token and refresh token.
        private async Task<string?> LoginAndCacheAsync(HttpClient client)
        {
            _logger.LogInformation("Requesting new access token from login endpoint");

            try
            {
                var loginUrl = $"{_ticketApiBaseUrl}/api/Auth/login";
                var loginRequest = new
                {
                    username = _apiUsername,
                    password = _apiPassword
                };

                var jsonContent = JsonSerializer.Serialize(loginRequest);
                var content = new StringContent(jsonContent, Encoding.UTF8, "application/json");

                var response = await client.PostAsync(loginUrl, content);

                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    _logger.LogError("Failed to get JWT token. Status: {StatusCode}, Error: {Error}",
                        response.StatusCode, errorContent);
                    return null;
                }

                var responseContent = await response.Content.ReadAsStringAsync();
                var loginResponse = JsonSerializer.Deserialize<LoginResponse>(responseContent, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });

                if (loginResponse?.Token == null || string.IsNullOrEmpty(loginResponse.RefreshToken))
                {
                    _logger.LogError("Login response did not contain a token");
                    return null;
                }

                lock (_tokenLock)
                {
                    // Store access + refresh tokens for reuse across requests.
                    _cachedToken = loginResponse.Token;
                    _tokenExpiry = loginResponse.ExpiresAt;
                    _cachedRefreshToken = loginResponse.RefreshToken;
                    _refreshTokenExpiry = loginResponse.RefreshExpiresAt;
                }

                _logger.LogInformation("Successfully obtained new JWT token for user: {Username}", loginResponse.Username);
                return loginResponse.Token;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while getting JWT token");
                return null;
            }
        }

        // Clears only the access token so the next call can attempt a refresh using the cached refresh token.
        private static void ClearCachedAccessToken()
        {
            lock (_tokenLock)
            {
                _cachedToken = null;
                _tokenExpiry = DateTime.MinValue;
            }
        }

        // Clears both access and refresh tokens (full reset).
        private static void ClearCachedToken()
        {
            lock (_tokenLock)
            {
                _cachedToken = null;
                _tokenExpiry = DateTime.MinValue;
                _cachedRefreshToken = null;
                _refreshTokenExpiry = DateTime.MinValue;
            }
        }
        // The main function entry point that handles incoming HTTP requests,
        //  forwards them to the Ticket API with the appropriate JWT token, 
        // and returns the response back to the client.
        [Function("TicketProxy")]
        public async Task<HttpResponseData> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", "post", "put", "delete", Route = "ticket/{*route}")] HttpRequestData req,
            string? route = null)
        {
            _logger.LogInformation("TicketProxy function triggered with method: {Method}, route: {Route}", req.Method, route);

            try
            {
                using var client = _httpClientFactory.CreateClient();

                // Get JWT token
                var token = await GetTokenAsync(client);
                if (string.IsNullOrEmpty(token))
                {
                    _logger.LogError("Failed to obtain JWT token");
                    var authErrorResponse = req.CreateResponse(System.Net.HttpStatusCode.Unauthorized);
                    await authErrorResponse.WriteAsJsonAsync(new { error = "Failed to authenticate with the Ticket API" });
                    return authErrorResponse;
                }

                // Build the target URL
                string targetUrl = $"{_ticketApiBaseUrl}/api/Ticket";
                if (!string.IsNullOrEmpty(route))
                {
                    // Preserve extra route segments like /ticket/{id}.
                    targetUrl += $"/{route}";
                }

                _logger.LogInformation("Forwarding request to: {TargetUrl}", targetUrl);

                // Create the request message
                var requestMessage = new HttpRequestMessage(new HttpMethod(req.Method), targetUrl);

                // Add JWT Bearer token
                requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

                // Copy headers from incoming request (excluding content-length and authorization)
                foreach (var header in req.Headers)
                {
                    if (!header.Key.Equals("content-length", StringComparison.OrdinalIgnoreCase) &&
                        !header.Key.Equals("authorization", StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            // Forward client headers where safe.
                            requestMessage.Headers.TryAddWithoutValidation(header.Key, header.Value);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning("Failed to add header {HeaderKey}: {ErrorMessage}", header.Key, ex.Message);
                        }
                    }
                }

                // Copy body if present (POST and PUT)
                if (req.Body.Length > 0)
                {
                    var body = await req.ReadAsStringAsync();
                    if (!string.IsNullOrEmpty(body))
                    {
                        // Preserve JSON payload for downstream API.
                        requestMessage.Content = new StringContent(body, Encoding.UTF8, 
                            System.Net.Http.Headers.MediaTypeHeaderValue.Parse("application/json"));
                    }
                }

                // Send the request
                var response = await client.SendAsync(requestMessage);

                // Handle 401 Unauthorized - token might be expired
                if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                {
                    _logger.LogWarning("Received 401 Unauthorized. Clearing access token and retrying...");
                    ClearCachedAccessToken();

                    // Retry once with a new token
                    var newToken = await GetTokenAsync(client);
                    if (!string.IsNullOrEmpty(newToken))
                    {
                        // Recreate the request
                        var retryRequest = new HttpRequestMessage(new HttpMethod(req.Method), targetUrl);
                        retryRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", newToken);

                        foreach (var header in req.Headers)
                        {
                            if (!header.Key.Equals("content-length", StringComparison.OrdinalIgnoreCase) &&
                                !header.Key.Equals("authorization", StringComparison.OrdinalIgnoreCase))
                            {
                                // Copy headers again for the retried request.
                                retryRequest.Headers.TryAddWithoutValidation(header.Key, header.Value);
                            }
                        }

                        if (req.Body.CanSeek)
                        {
                            // Reset stream to allow reread on retry.
                            req.Body.Position = 0;
                        }

                        if (req.Body.Length > 0)
                        {
                            var body = await req.ReadAsStringAsync();
                            if (!string.IsNullOrEmpty(body))
                            {
                                // Reapply JSON payload on retry.
                                retryRequest.Content = new StringContent(body, Encoding.UTF8,
                                    System.Net.Http.Headers.MediaTypeHeaderValue.Parse("application/json"));
                            }
                        }

                        response = await client.SendAsync(retryRequest);
                    }
                }

                // Read response content as bytes
                var contentBytes = await response.Content.ReadAsByteArrayAsync();

                // Create the response
                var responseData = req.CreateResponse(response.StatusCode);

                // Copy content type header
                if (response.Content.Headers.ContentType != null)
                {
                    // Preserve upstream content type if provided.
                    responseData.Headers.Add("Content-Type", response.Content.Headers.ContentType.ToString());
                }
                else
                {
                    responseData.Headers.Add("Content-Type", "application/json");
                }

                // Write the body with bytes
                if (contentBytes.Length > 0)
                {
                    // Return raw bytes to preserve exact upstream response.
                    await responseData.Body.WriteAsync(contentBytes, 0, contentBytes.Length);
                }

                return responseData;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred: {ErrorMessage}", ex.Message);
                var errorResponse = req.CreateResponse(System.Net.HttpStatusCode.InternalServerError);
                await errorResponse.WriteAsJsonAsync(new { error = ex.Message });
                return errorResponse;
            }
        }

        
        private class LoginResponse
        {
            public string Token { get; set; } = string.Empty;
            public string Username { get; set; } = string.Empty;
            public string Role { get; set; } = string.Empty;
            public DateTime ExpiresAt { get; set; }
            public string RefreshToken { get; set; } = string.Empty;
            public DateTime RefreshExpiresAt { get; set; }
        }
    }
}
