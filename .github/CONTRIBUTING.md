# Contribution Guide

### Code of Conduct

This project is committed to fostering a welcoming and inclusive community. As a contributor,
you agree to uphold the principles outlined in the [Code of Conduct](./CODE_OF_CONDUCT.md). If
you have concerns or encounter any unacceptable behavior, please reach out to mta.coder97@gmail.com.

---

### I Want To Contribute

> ### Legal Notice
>
> By contributing to this project, you agree that you are the original author of the contributed material and that you have the necessary rights to contribute it, and that the contributed material may be distributed under the project's license.

### Submit issues

### Reporting bugs

We rely on bug reports to enhance this project for all users. To assist us, we have a bug reporting template specifying the necessary details. Ensure you check our [existing bug reports](https://github.com/GoBetterAuth/go-better-auth/issues?q=is%3Aissue+is%3Aopen+label%3Abug) prior to submitting a new one to avoid duplicates.

### Reporting security issues

Avoid creating a public GitHub issue for security concerns. If you discover a security vulnerability, contact us directly via email at mta.coder97@gmail.com rather than opening an issue.

### Requesting new features

To request new features, please create an issue on this project.
To ensure that we can understand the problem you are looking to solve, please be as detailed as possible.
To see what other people have already suggested, you can look [here](https://github.com/GoBetterAuth/go-better-auth/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement).
Please be aware that duplicate issues might already exist. If you are creating a new issue, please check existing open, or recently closed. Having a single vote for an issue is far easier for us to prioritise.

---

### Begin Contributing

#### Requirements

To start contributing:

- [Fork](https://docs.github.com/en/github/getting-started-with-github/fork-a-repo) the repository
- Clone the fork on your workstation:

  ```bash
  $ git clone git@github.com:{YOUR_USERNAME}/go-better-auth.git

  $ cd go-better-auth
  ```

Choose one of the following development setups:

1. `Devcontainers`:

Once you have this repo cloned to your local system, you will need to install the VSCode extension [Remote Development](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.vscode-remote-extensionpack).

Then run the following command from the command palette:
`Dev Containers: Open Folder in Container...`

This will automatically select the workspace folder. But if you need to find the project manually then it is located at `/workspaces/go-better-auth`. You can then proceed to the development section below.

2. `Without devcontainers`:

- Make sure to install [Go](https://go.dev/doc/install) and set it up as shown in their docs.

#### Development:

1. **Install Dependencies**

- Once you have your environment set up and you are within the project, run `go mod download && go mod tidy` to install Go dependencies.

- Then as a test run `make build` to ensure the project builds successfully, this could take a few seconds to a minute.

2. **Project Structure**

- Code is organised by Go Clean Architecture:
  - `domain/` – core models and interfaces
  - `usecase/` – business logic
  - `repository/` – data access implementations
  - `handler/` – HTTP handlers
  - `infrastructure/` – configurations and tooling

3. **Testing**

- Run unit and integration tests:

  ```bash
  # Run all tests
  make test

  # Run specific tests
  go test -v ./usecase/auth -run TestSignUp|TestSignIn
  ```

4. **Making Changes**

- Follow the project’s folder structure.
- Write tests for new features.
- Ensure all code passes tests before submitting a PR.

5. **Submitting a PR**

- Push your branch and open a pull request.
- Fill out the PR and link related issues.

---
