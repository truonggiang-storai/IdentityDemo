using Identity.Domain.Enums;
using Identity.Domain.Exceptions;
using Identity.Domain.SharedKernel;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http;
using System.Net;
using System.Security.Authentication;
using System.Text.Json;

namespace Identity.CustomMiddlewares
{
    public class ExceptionHandlingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ExceptionHandlingMiddleware> _logger;

        public ExceptionHandlingMiddleware(RequestDelegate next, ILogger<ExceptionHandlingMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext httpContext, IHostEnvironment env)
        {
            try
            {
                await _next(httpContext);
            }
            catch (Exception ex)
            {
                await HandleExceptionAsync(httpContext, ex, env);
            }
        }

        private async Task HandleExceptionAsync(HttpContext context, Exception exception, IHostEnvironment env)
        {
            var code = HttpStatusCode.InternalServerError;

            var responseObject = new BaseResponseObject
            {
                Status = false,
                ErrorCode = ResponseErrorCode.UnhandleException,
                Message = exception.Message,
                StackTrace = env.IsProduction() ? string.Empty : exception.StackTrace,
                Data = exception.Data
            };

            switch (exception)
            {
                case ArgumentNullException _:
                    code = HttpStatusCode.BadRequest;
                    responseObject.ErrorCode = ResponseErrorCode.ArgumentNullException;
                    break;
                case ArgumentOutOfRangeException _:
                    code = HttpStatusCode.BadRequest;
                    responseObject.ErrorCode = ResponseErrorCode.ArgumentOutOfRangeException;
                    break;
                case ArgumentException _:
                    code = HttpStatusCode.BadRequest;
                    responseObject.ErrorCode = ResponseErrorCode.ArgumentException;
                    break;
                case NotFoundException _:
                    code = HttpStatusCode.NotFound;
                    responseObject.ErrorCode = ResponseErrorCode.NotFound;
                    break;
                case InvalidOperationException _:
                    code = HttpStatusCode.BadRequest;
                    responseObject.ErrorCode = ResponseErrorCode.InvalidOperationException;
                    break;
                case AuthenticationException _:
                    code = HttpStatusCode.BadRequest;
                    responseObject.ErrorCode = ResponseErrorCode.AuthenticationException;
                    break;
            }

            _logger.LogError(exception.Message);
            var result = JsonSerializer.Serialize(responseObject);

            context.Response.ContentType = "application/json";
            context.Response.StatusCode = (int)code;
            await context.Response.WriteAsync(result);
        }
    }
}
