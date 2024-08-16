# Cookiecutter template for Binary Ninja Plugins

This Cookiecutter template helps you quickly set up a new Binary Ninja plugin project that is simple, structured, maintainable, and readable.

- **Goals**
  - Create a Binary Ninja plugin project that is:
    - Simple
    - Readable
    - Maintainable
- **Non-Goals**
  - Create a plugin that:
    - Does everything for you
    - Is overly complex
    - Serves as a comprehensive cheat sheet

## Quick Start

1. **Install cookiecutter**

    ```bash
    # Recommended: Install with pipx
    pipx install cookiecutter

    # Alternative: Use pip
    python -m pip install cookiecutter
    ```

2. **Generate** your plugin project  
    Choose one of the following methods for interactive generation:

    ```bash
    # Using Cookiecutter from remote GitHub repository
    pipx run cookiecutter gh:rand-tech/cookiecutter-binary-ninja-plugin

    # Using a local clone 
    git clone github.com/rand-tech/cookiecutter-binary-ninja-plugin
    cookiecutter ./cookiecutter-binary-ninja-plugin
    ```

    For non-interactive generation, use the `--no-input` option:

    Example:

    ```bash
    cookiecutter gh:rand-tech/cookiecutter-binary-ninja-plugin --no-input \
        plugin_type=helper \
        plugin_name="Artifact Sharing" \
        author_name="Your Name" \
        author_email="you@example.com" \
        description="Load/Export artifacts" \
        long_description="This plugin allows you to load and export artifacts to/from Binary Ninja." \
        version="0.1.0" \
        license="MIT" \
        minimum_binary_ninja_version="776"
    ```

3. **Install** your plugin  
    Copy your new plugin directory to Binary Ninja's plugin folder:

   - macOS: `~/'Library/Application Support/Binary Ninja'/plugins/`
   - Linux: `~/.binaryninja/plugins/`
   - Windows: `%APPDATA%\Binary Ninja\plugins\`

4. **Load** you plugin
    1. **Restart Binary Ninja** to load your plugin.
    1. **Verify** that the plugin loaded successfully in the console.
5. **Develop** your plugin, making changes as needed.

Make changes to your plugin code as needed. Repeat steps 3-5 during development.

### Development Tips

- **Speed up restarts:** Temporarily disable other plugins:

  ```bash
  BN_DISABLE_REPOSITORY_PLUGINS=True
  ```

- **Enable IDE support:** Install the Binary Ninja API:

  ```bash
  python3 /path/to/scripts/install_api.py
  ```

    For specific paths, refer to the [Binary Ninja documentation](https://docs.binary.ninja/guide/index.html#binary-path).

  - macOS: `/Applications/Binary Ninja.app/Contents/Resources/scripts/install_api.py`

### Submitting Your Plugin

When your plugin is ready, follow the [official submission guidelines](https://docs.binary.ninja/dev/plugins.html#submitting-to-the-plugin-manager) to add it to the Binary Ninja Plugin Manager.

## Troubleshooting

If you encounter installation issues related to Binary Ninja, consult the [official Binary Ninja documentation](https://docs.binary.ninja/guide/index.html#user-folder) for up-to-date information on plugin directories and installation procedures.

## Development Status

- [ ] Supported plugin types:
  - [x] Helper
  - [x] Binary View
  - [x] UI (*partial*)
  - [x] Architecture (*partial*)
  - [ ] Core
- [ ] Refactor and improve the template
  - [ ] Improve the project structure
- [ ] Support venv (pydantic)  
  - Using venv (pydantic) is good if you are working on a single plugin for a long time. However, it is not a good solution for small plugins considering how Binary Ninja handles and executes plugins.
  - If using pydantic, set these Binary Ninja settings:
    - **`python.virtualenv`** `/path/to/.venv/lib/python3.11/site-packages`
    - **`python.binaryOverride`** `/path/to/.venv/bin/python`

## Resources

- List of useful links
  - [Writing Plugins - Vector 35](https://docs.binary.ninja/dev/plugins.html)
  - <https://github.com/Vector35/official-plugins>
  - <https://github.com/Vector35/community-plugins>
  - <https://github.com/Vector35/binaryninja-api/tree/dev/python/examples>
  - <https://gist.github.com/alexander-hanel/ab801910e594ec60f07d7583873ddac0>
  - Architecture Plugin Development
    - [A Guide to Architecture Plugins (Part 1) - Vector 35](https://binary.ninja/2020/01/08/guide-to-architecture-plugins-part1.html)
    - [A Guide To Architecture Plugins (Part 2) - Vector 35](https://binary.ninja/2021/12/09/guide-to-architecture-plugins-part2.html)
    - [Leveraging Binary Ninja IL to Reverse a Custom ISA: Cracking the “Pot of Gold” 37C3 - Synacktiv](https://www.synacktiv.com/en/publications/leveraging-binary-ninja-il-to-reverse-a-custom-isa-cracking-the-pot-of-gold-37c3)
    - <https://github.com/hgarrereyn?tab=repositories&q=bn->

## Feedback and Contributions

This project is a work in progress. Your feedback and experiences are valuable:

- For issues or suggestions, please open an issue.
- Contributions via pull requests are welcome.

Thank you for your interest and support!
