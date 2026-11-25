# Environment configuration

The .env file is included with this project for examination and evaluation purposes. It provides the configuration required to run the services locally without additional setup.

This is not a production environment.

# Authentication Service

This service stores accounts in the `invex` database and issues the access token. The token subject is the username.

The same MySQL server creates the empty `invex_employees` database for Employee Service. Tables from one service do not live in the other service's database.

From this folder:

```bash
docker compose up --build -d
```

Compose reads `.env`.

Swagger: `http://localhost:8080/swagger-ui/index.html`

These accounts already exist:

- `admin` / `admin`, `admin@test.invex.local`, role `ADMIN`.
- `employee` / `employee`, `employee@test.invex.local`, role `EMPLOYEE`.

In Swagger, choose Authorize. The client is `employee-management-client` and the grant is Authorization Code with PKCE. Sign in as `admin` / `admin`. Swagger sends the access token as Bearer.

Account creation is `POST /api/v1/security/accounts` with the admin token. The body is `username`, `password`, `email` and `role`. An employee account uses the role `EMPLOYEE`. The response does not include the password. A repeated username or a repeated email, including a change of letter case, returns 409.

`POST /api/v1/security/accounts/batch` accepts several accounts in one request. Each item is `username`, `password` and `email`. The role is `EMPLOYEE`. The response has one result per item, in the same order. A conflict on one account does not undo the others. Each result has `status` `CREATED`, `CONFLICT` or `INVALID`.

`POST /api/v1/security/accounts/validate` checks whether a username or an email is already registered. The email comparison ignores letter case. An account with `enabled` false still exists. The response reports `usernameExists` and `emailExists` for each item.

`DELETE /api/v1/security/accounts/{username}` removes the account from `users`. The response is 204 with an empty body. A missing username returns 404. An access token issued before the deletion remains valid until it expires.

Employee Service opens that account when it creates an employee. The link between the account and the employee is the username. When Employee Service deletes an employee, it calls the delete operation above before removing the employee.

Tests:

```bash
./gradlew clean build
```
