# 🎉 Contributing to unix-audit.py

We warmly welcome contributions to `unix-audit.py`! Your help in making this a more robust and comprehensive security auditing tool is highly appreciated.

## 🤝 How You Can Contribute

There are many ways you can contribute, including:

* **Reporting Bugs:** If you encounter any issues or unexpected behavior, please open a new issue on GitHub. Be as detailed as possible, including steps to reproduce the bug, your operating system, and the version of Python you are using.
* **Suggesting Enhancements:** Have an idea for a new audit check, a feature improvement, or a better way to present the results? We'd love to hear it! Open a new issue with your suggestion and explain your reasoning.
* **Writing Code:** You can contribute directly by implementing new audit checks, fixing bugs, or improving the existing codebase.
* **Improving Documentation:** Help us make the documentation clearer, more comprehensive, and easier to understand. This includes the README, any inline comments, or additional guides.
* **Testing:** Help us ensure the reliability of the script by testing new features and bug fixes.

## 🛠️ Getting Started with Code Contributions

Ready to dive into the code? Here's how:

1.  **Fork the Repository:** Click the "Fork" button at the top right of the [GitHub repository](https://github.com/HackingRepo/unix-audit). This will create a copy of the project under your GitHub account.

2.  **Clone Your Fork:** Clone the repository to your local machine:
    ```bash
    git clone [https://github.com/your-username/unix-audit.git](https://github.com/your-username/unix-audit.git)
    cd unix-audit
    ```
    (Replace `your-username/your-repo` with the URL of your forked repository.)

3.  **Create a New Branch:** Create a dedicated branch for your changes. This helps keep your work isolated and makes it easier to manage pull requests.
    ```bash
    git checkout -b feature/your-new-feature
    # or
    git checkout -b fix/your-bug-fix
    ```

4.  **Make Your Changes:** Implement your new feature, bug fix, or improvement. Follow the existing code style and conventions. Add comments to explain your code where necessary.

5.  **Test Your Changes:** Ensure your changes work as expected and don't introduce any new issues. If you're adding a new audit check, make sure it's accurate and provides useful information.

6.  **Commit Your Changes:** Commit your changes with clear and concise commit messages. Follow the [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/) specification if possible.
    ```bash
    git add .
    git commit -m "feat: Add new check for insecure permissions"
    # or
    git commit -m "fix: Resolve issue with user enumeration"
    ```

7.  **Push to Your Fork:** Push your local branch to your forked repository on GitHub:
    ```bash
    git push origin feature/your-new-feature
    ```

8.  **Create a Pull Request:** Go to the [GitHub repository](https://github.com/your-username/your-repo) and click the "Compare & pull request" button. Provide a clear and descriptive title and explain the purpose of your changes in the body of the pull request.

## 📏 Code Style Guidelines

Please try to adhere to the following guidelines when contributing code:

* **Python Style:** Follow the [PEP 8](https://peps.python.org/pep-0008/) style guide for Python code. You can use tools like `flake8` or `pylint` to help ensure your code conforms to these standards.
* **Clear Naming:** Use descriptive names for variables, functions, and modules.
* **Comments:** Add comments to explain complex logic or important sections of your code.
* **Modularity:** Try to keep your code modular and well-organized. New audit checks should ideally be implemented as separate functions or classes.
* **Error Handling:** Implement proper error handling to make the script more robust.

## 🧪 Testing Guidelines

* **Thorough Testing:** Test your changes on different Unix-like systems if possible to ensure cross-compatibility.
* **Add Test Cases:** If you're adding new functionality, consider adding relevant test cases to ensure it continues to work as expected in the future.

## 📝 Documentation Guidelines

* **Clear and Concise:** Write clear and concise documentation.
* **Examples:** Provide examples where applicable to illustrate how to use new features or understand specific aspects of the script.
* **Update README:** If you add or change significant functionality, make sure to update the `README.md` file accordingly.

## 🙏 Thank You!

Your contributions, no matter how big or small, help make `unix-audit.py` a better tool for everyone. We appreciate your time and effort!

---

If you have any questions or need help, feel free to reach out by opening an issue.
