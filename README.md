# API de Autenticação JWT com Spring Boot

Este projeto implementa uma API REST com autenticação JWT (JSON Web Token) usando Spring Boot, Spring Security e H2 Database.

## Tecnologias Utilizadas

- Java 21 (LTS)
- Spring Boot 3.2.3
- Spring Security
- Spring Data JPA
- H2 Database
- JWT
- Lombok
- Maven

## Configuração do Ambiente

1. Certifique-se de ter o JDK 21 instalado
2. Clone o repositório
3. Execute o projeto:
   ```bash
   mvn spring-boot:run
   ```

## Endpoints da API

### 1. Registro de Usuário (Signup)
```http
POST http://localhost:8080/api/auth/signup
Content-Type: application/json

{
    "username": "admin",
    "email": "admin@email.com",
    "password": "senha123",
    "role": ["admin"]
}
```

### 2. Login (Signin)
```http
POST http://localhost:8080/api/auth/signin
Content-Type: application/json

{
    "username": "admin",
    "password": "senha123"
}
```

Resposta do login:
```json
{
    "token": "eyJhbGciOiJIUzI1NiJ9...",
    "type": "Bearer",
    "id": 1,
    "username": "admin",
    "email": "admin@email.com",
    "roles": ["ROLE_ADMIN"]
}
```

### 3. Endpoints Protegidos

#### Conteúdo Público
```http
GET http://localhost:8080/api/test/all
```

#### Conteúdo do Usuário (requer autenticação)
```http
GET http://localhost:8080/api/test/user
Authorization: Bearer seu_token_jwt
```

#### Conteúdo do Administrador (requer role ADMIN)
```http
GET http://localhost:8080/api/test/admin
Authorization: Bearer seu_token_jwt
```

## Como Testar com Postman

### 1. Criar Usuário (Signup)
1. Abra o Postman
2. Crie uma nova requisição POST para `http://localhost:8080/api/auth/signup`
3. Vá em "Headers" e adicione:
   - Key: `Content-Type`
   - Value: `application/json`
4. Vá em "Body", selecione "raw" e "JSON", cole:
   ```json
   {
       "username": "admin",
       "email": "admin@email.com",
       "password": "senha123",
       "role": ["admin"]
   }
   ```
5. Clique em "Send"

### 2. Fazer Login (Signin)
1. Crie uma nova requisição POST para `http://localhost:8080/api/auth/signin`
2. Configure os mesmos headers do signup
3. No body, cole:
   ```json
   {
       "username": "admin",
       "password": "senha123"
   }
   ```
4. Clique em "Send"
5. Copie o token da resposta

### 3. Acessar Endpoints Protegidos
1. Crie uma nova requisição GET para `http://localhost:8080/api/test/admin`
2. Vá em "Authorization"
3. Selecione "Bearer Token"
4. Cole o token no campo "Token"
5. Clique em "Send"

## Banco de Dados H2

O projeto usa H2 Database em memória. Para acessar o console H2:

1. Acesse `http://localhost:8080/h2-console`
2. Use as seguintes credenciais:
   - JDBC URL: `jdbc:h2:mem:testdb`
   - Username: `sa`
   - Password: `password`

## Estrutura do Projeto

```
src/main/java/com/example/jwtauthdemo/
├── controller/
│   ├── AuthController.java
│   └── TestController.java
├── model/
│   ├── User.java
│   ├── Role.java
│   └── ERole.java
├── repository/
│   ├── UserRepository.java
│   └── RoleRepository.java
├── security/
│   ├── jwt/
│   │   ├── AuthEntryPointJwt.java
│   │   ├── AuthTokenFilter.java
│   │   └── JwtUtils.java
│   ├── services/
│   │   ├── UserDetailsImpl.java
│   │   └── UserDetailsServiceImpl.java
│   └── WebSecurityConfig.java
└── payload/
    ├── request/
    │   ├── LoginRequest.java
    │   └── SignupRequest.java
    └── response/
        ├── JwtResponse.java
        └── MessageResponse.java
```

## Solução de Problemas

### Erro 401 (Não Autorizado)
- Verifique se o token está sendo enviado corretamente no header
- Certifique-se que o token não expirou
- Verifique se o usuário tem a role necessária

### Erro 403 (Proibido)
- Verifique se o usuário tem a role necessária para acessar o recurso
- Verifique se o token está válido

### Erro 500 (Erro Interno)
- Verifique os logs do servidor para mais detalhes
- Certifique-se que o banco de dados está funcionando corretamente
