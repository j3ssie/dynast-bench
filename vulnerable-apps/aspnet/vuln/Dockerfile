FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY BenchAspNet.csproj ./
RUN --mount=type=cache,target=/root/.nuget/packages dotnet restore
COPY . ./
RUN --mount=type=cache,target=/root/.nuget/packages dotnet publish -c Release -o /out --no-restore
FROM mcr.microsoft.com/dotnet/aspnet:8.0-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /out ./
RUN mkdir -p /data/uploads /data/files && printf 'public report\n' > /data/files/readme.txt
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --retries=30 --start-period=120s CMD curl -sf http://localhost:8080/api/_verify/health || exit 1
ENTRYPOINT ["dotnet", "BenchAspNet.dll"]
