# Contributing to WebHunter

Thank you for your interest in contributing to WebHunter! We welcome contributions from the community to help make this tool better.

## 📜 Code of Conduct

By participating in this project, you agree to:
- Be respectful and inclusive
- Provide constructive feedback
- Focus on what is best for the community
- Show empathy towards other community members

## 🐛 Reporting Bugs

Before submitting a bug report:
1. **Check existing issues** to avoid duplicates
2. **Use the latest version** of WebHunter
3. **Verify the issue** is reproducible

When reporting bugs, include:
- **Description**: Clear description of the issue
- **Steps to reproduce**: Detailed steps to recreate the bug
- **Expected behavior**: What you expected to happen
- **Actual behavior**: What actually happened
- **Environment**: OS, Rust version, WebHunter version
- **Logs/Screenshots**: Any relevant error messages or screenshots

## 💡 Suggesting Features

We love feature suggestions! To suggest a feature:
1. **Check existing issues** to see if it's already proposed
2. **Open a new issue** with the "feature request" label
3. **Describe the feature** and its use case
4. **Explain the benefits** to users

## 🔧 Development Setup

### Prerequisites
- Rust 1.70 or higher
- Git
- A code editor (VS Code, IntelliJ IDEA, etc.)

### Setup Steps

1. **Fork the repository** on GitHub

2. **Clone your fork**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/Project-WebHunter.git
   cd Project-WebHunter
   ```

3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/VenTheZone/Project-WebHunter.git
   ```

4. **Build the project**:
   ```bash
   cargo build
   ```

5. **Run tests** (if available):
   ```bash
   cargo test
   ```

## 🔄 Development Workflow

1. **Create a branch** for your work:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**:
   - Write clean, readable code
   - Follow Rust conventions and idioms
   - Add comments for complex logic
   - Update documentation as needed

3. **Test your changes**:
   ```bash
   cargo build
   cargo run -- --help
   # Test your specific changes
   ```

4. **Commit your changes**:
   ```bash
   git add .
   git commit -m "feat: add your feature description"
   ```
   
   Use conventional commit messages:
   - `feat:` for new features
   - `fix:` for bug fixes
   - `docs:` for documentation changes
   - `refactor:` for code refactoring
   - `test:` for adding tests
   - `chore:` for maintenance tasks

5. **Keep your branch updated**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

6. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

## 📝 Pull Request Guidelines

### Before Submitting

- ✅ Code builds without errors (`cargo build`)
- ✅ Code follows Rust conventions
- ✅ Documentation is updated if needed
- ✅ Commit messages are clear and descriptive
- ✅ Branch is up-to-date with main

### Submitting a Pull Request

1. **Open a PR** from your fork to the main repository
2. **Fill out the PR template** with:
   - Description of changes
   - Related issue numbers (if applicable)
   - Testing performed
   - Screenshots (if UI changes)
3. **Wait for review** - maintainers will review your PR
4. **Address feedback** - make requested changes if needed
5. **Celebrate!** 🎉 Once approved, your PR will be merged

### PR Best Practices

- Keep PRs focused on a single feature or fix
- Write clear PR descriptions
- Respond to review comments promptly
- Be open to feedback and suggestions
- Update your PR if the main branch changes

## 🎨 Coding Standards

### Rust Style
- Follow the [Rust Style Guide](https://doc.rust-lang.org/1.0.0/style/)
- Use `cargo fmt` to format code
- Use `cargo clippy` to catch common mistakes

### Code Organization
- Keep functions focused and concise
- Use meaningful variable and function names
- Add comments for complex algorithms
- Organize code into logical modules

### Documentation
- Document public APIs with doc comments (`///`)
- Update README.md for user-facing changes
- Update pseudo-code documentation for algorithm changes
- Include examples in documentation

## 🧪 Testing

Currently, WebHunter relies on manual testing. When contributing:

1. **Test your changes** against known vulnerable applications:
   - [DVWA](http://www.dvwa.co.uk/)
   - [WebGoat](https://owasp.org/www-project-webgoat/)
   - [bWAPP](http://www.itsecgames.com/)

2. **Verify scanner functionality**:
   - Test with valid targets
   - Test with invalid inputs
   - Check error handling
   - Verify report generation

3. **Document your testing** in the PR description

## 📚 Documentation Contributions

Documentation improvements are highly valued! You can contribute by:

- Fixing typos or grammatical errors
- Improving clarity of explanations
- Adding examples and use cases
- Updating pseudo-code documentation
- Creating tutorials or guides

## 🔐 Security Contributions

If you're contributing security-related features:

1. **Follow responsible disclosure** practices
2. **Don't include exploits** for real-world vulnerabilities
3. **Test thoroughly** to avoid false positives/negatives
4. **Document detection methods** clearly
5. **Consider ethical implications**

## ❓ Questions?

If you have questions about contributing:
- Open a discussion on GitHub
- Check existing issues and PRs
- Review the [pseudo-code documentation](pseudo-code/README.md)

## 🙏 Thank You!

Your contributions help make WebHunter better for everyone. We appreciate your time and effort!

---

**Happy Contributing!** 🚀
