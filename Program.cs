var builder = WebApplication.CreateBuilder(args);

// Add CORS services
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowRequests", policy =>
    {
        policy.AllowAnyOrigin() // Allow any origin
              .AllowAnyHeader()
              .AllowAnyMethod();
        // Remove .AllowCredentials() if you are using AllowAnyOrigin()
        // If you need to use AllowCredentials(), then specify .WithOrigins("https://example.com") instead of AllowAnyOrigin()
    });
});

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// Apply CORS middleware before Authorization and MapControllers
app.UseCors("AllowRequests");

app.UseAuthorization();

app.MapControllers();

app.Run();
