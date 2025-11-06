### General Guidelines

- Keep things loosely coupled.

- Make sure to implement every feature until completion. Avoid creating mock data for features, implement everything with a real implementation.

---

### Backend

- Develop the code within the root of the directory.

- Only use the `slog` package for logging. Configure it to output logs in a human-readable format.

- Make sure the imports follow the following structure with spaces between each section:

  - Standard library imports
  - Third-party imports
  - Internal imports

- Coding guide:

  - Follow Go's official coding style as outlined in Effective Go and Go Code Review Comments.
  - Use `gofmt` or `goimports` to format code consistently.
  - Use meaningful variable and function names that convey intent.
  - Keep functions small and focused on a single responsibility.
  - Write comments for complex logic, exported functions, and types.
  - Prefer to use `any` instead of `interface{}` for better readability.

- Project Layout (Go Clean Architecture):

  - Organize the codebase into the following main layers:
    - `domain/`: Contains domain models (entities), domain-specific interfaces, and business rules. This layer is independent of frameworks and external libraries.
    - `usecase/`: Contains application-specific business logic (use cases) that orchestrate domain operations. Use cases depend only on the domain layer and define interfaces for repositories and external services.
    - `repository/`: Contains implementations of repository interfaces defined in the domain or usecase layers. Handles data persistence and external service integration.
    - `handler/`: Contains HTTP handlers, gRPC servers, or other delivery mechanisms. Responsible for parsing requests, invoking use cases, and formatting responses.
    - `infrastructure/`: Contains concrete implementations for database access, external APIs, logging, configuration, etc. Implements interfaces defined in the domain or usecase layers.
  - Each feature or domain should have its own subfolder within these layers (e.g., `domain/user`, `usecase/user`, `repository/user`).
  - Dependencies should always point inward: handler/infrastructure → usecase → domain.
  - Use dependency injection to provide implementations to use cases and handlers.
  - Keep domain and usecase layers free of framework-specific code for maximum testability and portability.
  - Make sure to add relevant json tags to structs that will be serialized to/from JSON especially if it's part of the request/response lifecycle between the frontend and backend.

- Modular Design:

  - Follow S.O.L.I.D principles and make sure that every feature and domain is separated into its own folder and relevant files. Make sure each code file is not very large and if needed separate it into multiple different files to make the code more readable, maintainable and testable. Always create interfaces to abstract away implementations and make the code loosely coupled.

- Error handling:

  - Return Errors Explicitly: Go's idiomatic way is to return errors as the last return value.
  - Wrap Errors: Use fmt.Errorf with %w to wrap errors, preserving the original error context. This allows for programmatic inspection using errors.Is and errors.As.

- Logging:

  - Structured Logging: Use structured loggers such as slog to output logs in a machine-readable format (JSON).
  - Contextual Logging: Pass a logger through the request context or as a dependency to functions, enriching logs with request-specific information (e.g., request ID, user ID).
  - Log Levels: Use appropriate log levels (DEBUG, INFO, WARN, ERROR, FATAL) for different severities.

- Configuration Management:

  - Manage application settings effectively.
  - Config Variables: Always provide properties within the main Base Config struct for all configuration variables.
  - Strict Validation: Validate configuration values at startup to catch errors early.

- Database Interactions

  - Efficient and safe database access.
  - Repository Pattern: Encapsulate database operations within a repository layer. This separates business logic from data access details and makes it easier to swap databases or ORMs.
  - Use `gorm` ORM, but avoid using it directly in handlers. Instead, create a repository layer that abstracts database operations.
  - Connection Pooling: Configure database connection pooling correctly to manage connections efficiently and prevent resource exhaustion.
  - Context for Database Operations: Always pass context. Context to database operations for timeout and cancellation.
  - Transactions: Use database transactions for operations that require atomicity (all or nothing).

- Middleware:

  - Leverage the base net/http package for middleware.

- Validation:

  - Ensure incoming data is valid.
  - Request Body Validation: Validate incoming JSON request bodies. Use libraries like `go-playground/validator/v10` for declarative validation.
  - Business Logic Validation: Perform additional validation within the service layer that depends on business rules or database lookups. Add the `validate:"required"` tag to struct fields to enforce required fields as well as other features that the validator provides.

- Testing:

  - Write comprehensive tests.
  - Unit Tests: Test individual functions and components in isolation. Mock external dependencies (database, external APIs).
  - Integration Tests: Test interactions between different components (e.g., handler -> usecase -> repository -> database). Use a test database or Docker Compose for dependencies.
  - End-to-End Tests: Test the entire application flow from the client perspective.
  - Table-Driven Tests: Use table-driven tests for multiple test cases, especially for handlers and validation.
  - Make sure that the tests reflect production too so that the tests are relevant and meaningful.
  - Always run `make test || grep "FAIL"` to run all tests and to detect any failing tests to fix.

- Security:

  - Implement security best practices.
  - Input Sanitization: Sanitize all user inputs to prevent injection attacks (SQL injection, XSS).
  - Authentication & Authorization:
    - Use secure authentication mechanisms (e.g., JWT, OAuth2).
    - Implement robust authorization checks (role-based access control, attribute-based access control).
  - Rate Limiting: Protect the library from abuse and DDoS attacks using rate limiting.
  - Mocking: Use Go's interfaces to enable easy mocking of dependencies for unit testing. Libraries like stretchr/testify/mock can be helpful.
  - DO NOT store plain text passwords/tokens in the DB. Always hash passwords using a strong hashing algorithm like bcrypt before storing them.

- Dependency Management:

  - Manage external libraries and modules.
  - Go Modules: Use Go Modules for dependency management.
  - Pin Dependencies: Pin specific versions of dependencies to ensure reproducible builds.
  - Vendoring (Optional): Consider vendoring dependencies for strict control over builds, especially in regulated environments.
  - Minimize Dependencies: Avoid unnecessary dependencies to reduce complexity and attack surface.

- Concurrency:

  - Go's concurrency features are powerful but require careful handling.
  - Goroutines & Channels: Use goroutines for concurrent execution and channels for safe communication between goroutines.
  - Context for Cancellation: Always pass context.Context to goroutines that perform long-running operations, allowing for graceful cancellation.
  - Avoid Race Conditions: Use sync.Mutex, sync.RWMutex, or channels to prevent race conditions when accessing shared resources.
  - Worker Pools: For CPU-bound or I/O-bound tasks, consider implementing worker pools to limit concurrent operations and manage resources.

- Observability

  - Provide support for observability via OpenTelemetry.

- Documentation & API Design
  - Clear and consistent API design.
  - RESTful Principles: Adhere to RESTful principles for API design (resources, HTTP methods, status codes).
  - Clear Endpoints: Design clear, predictable, and versioned API endpoints.
  - API Documentation: Document your API using OpenAPI/Swagger. Tools like swag can generate this from Go code annotations.
  - Consistent Response Formats: Use consistent JSON response formats for success and error messages.

By following these best practices, you can build the library in a robust, scalable, and easy to maintain manner.

---
