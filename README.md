<p align="center">
  <img src="./project-logo.png" height="150" width="150" alt="Project Logo"/>
</p>

<p align="center">
 A comprehensive, framework-agnostic authentication and authorization library for Go.
</p>

---

**Note:** This project is still a work in progress. Contributions are most welcome!

---

### Table of Contents

1.  [Introduction](#introduction)
1.  [Features](#features)
1.  [Docs](#docs)
1.  [Contributing](#contributing)

---

### Introduction

✨ Overview

**GoBetterAuth** is a comprehensive, authentication and authorization library/framework for Go applications. It provides secure email/password authentication, social OAuth providers, session management, email verification, password reset, and more, all built with clean architecture principles.

💭 Why GoBetterAuth?

**GoBetterAuth** is designed to be a comprehensive authentication and authorization solution for Go applications. It simplifies the implementation of common security features while providing a clean and modular architecture. This way developers can focus on building their applications without worrying about the complexities of authentication and the time it takes to implement these features.

---

### Features

- 🔑 **Email & Password Authentication** – Secure, production-ready authentication with argon2 password hashing
- 🌐 **Social OAuth Providers** – Google, GitHub, Discord, and extensible generic OAuth2 support
- 🔐 **Session Management** – Secure, customizable session handling with refresh and expiration controls
- ✉️ **Email Verification** – Optional, configurable email verification workflow
- 🔄 **Password Reset** – Secure password reset with customizable email callbacks
- 🏗️ **Clean Architecture** – Go Clean Architecture: domain, usecase, repository, handler, and infrastructure layers
- 🔌 **Plugin System** – Extensible plugin architecture for custom business logic and routes
- 💾 **Multiple Database Support** – SQLite and PostgreSQL adapters, with migration scripts included
- 🛡️ **Security First** – CSRF protection, secure cookies, rate limiting, and input validation
- ⚡ **Rate Limiting** – Configurable, per-endpoint rate limiting with memory or database storage
- 🔁 **Token Refresh Flow** – Automatic token refresh and session extension
- 📦 **Minimal Dependencies** – Standard library first, production-ready, and framework-agnostic
- 🧩 **Comprehensive Configuration** – Flexible, type-safe config with sensible defaults and environment variable support
- 🧪 **Test Coverage** – Unit, integration, and E2E tests reflecting production scenarios

---

### Docs

For more info and a full guide on how to use this library, check out the [Docs](https://go-better-auth.vercel.app/docs).

---

### Contributing

Your contributions are welcome! Here's how you can get involved:

- If you find a bug, please [submit an issue](https://github.com/GoBetterAuth/go-better-auth/issues).
- Set up your development environment by following our [Contribution Guide](./contribution-guide.md).
- Contribute code by making a [pull request](https://github.com/GoBetterAuth/go-better-auth/) to enhance features, improve user experience, or fix issues.

---

### Support & Community

- [Discord Server](https://discord.gg/nThBksdr2Z)

---
