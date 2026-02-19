# Ticket Management Function

This is an Azure Function that acts as a proxy to the TicketManagement API. It forwards all incoming HTTP requests (GET, POST, PUT, DELETE) to the underlying TicketManagement API.

## Features

- **HTTP Proxy**: Forwards HTTP requests to the TicketManagement API
- **Method Support**: Supports GET, POST, PUT, and DELETE operations
- **Dynamic Routing**: Routes requests to `/api/ticket/{*route}` endpoint
- **Logging**: Built-in logging for debugging and monitoring
- **Error Handling**: Comprehensive error handling with appropriate HTTP status codes

## Prerequisites

- .NET 8.0 or later
- Azure Functions Core Tools (optional, for local development)

## Configuration

The function reads the `TicketApiBaseUrl` from environment variables. By default, it uses `http://localhost:5000`.

Update `local.settings.json` to change the base URL:

```json
{
  "Values": {
    "TicketApiBaseUrl": "http://localhost:5000"
  }
}
```

## Running Locally

### Option 1: Using Azure Functions Core Tools
```bash
func start
```

### Option 2: Using dotnet CLI
```bash
dotnet run
```

The function will be available at `http://localhost:7072`

## Available Endpoints

- **Get all tickets**: `GET /api/ticket`
- **Get ticket by ID**: `GET /api/ticket/{id}`
- **Create ticket**: `POST /api/ticket`
- **Update ticket**: `PUT /api/ticket/{id}`
- **Delete ticket**: `DELETE /api/ticket/{id}`

## Testing

Use the included `TicketManagementFunction.http` file to test the endpoints:

```
### Get all tickets
GET http://localhost:7072/api/ticket
```

## Project Structure

```
TicketManagementFunction/
├── TicketProxyFunction.cs       # Main function implementation
├── Program.cs                    # Application startup
├── host.json                     # Function host configuration
├── local.settings.json           # Local development settings
├── TicketManagementFunction.http # HTTP test requests
└── TicketManagementFunction.csproj # Project file
```

## Dependencies

- Microsoft.Azure.Functions.Worker
- Microsoft.Azure.Functions.Worker.Extensions.Http
- Microsoft.Extensions.Http
