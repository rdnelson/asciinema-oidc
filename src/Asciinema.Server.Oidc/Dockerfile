FROM mcr.microsoft.com/dotnet/sdk:5.0 AS build

WORKDIR /src
COPY Asciinema.Server.Oidc.csproj .
RUN dotnet restore

COPY . .
RUN dotnet publish -c Release

FROM mcr.microsoft.com/dotnet/aspnet:5.0
WORKDIR /app
COPY --from=build /src/bin/Release/net5.0/publish/ /app
ENTRYPOINT [ "/app/Asciinema.Server.Oidc" ]