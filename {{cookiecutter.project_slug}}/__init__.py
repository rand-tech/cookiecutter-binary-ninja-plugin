""" {{ cookiecutter.plugin_name }}
{{ cookiecutter.description }}
"""
from .const import PLUGIN_AUTHOR
__version__ = "{{ cookiecutter.version }}"
__author__ = PLUGIN_AUTHOR

{% if cookiecutter.plugin_type == 'helper' %}
from binaryninja import BinaryView, PluginCommand, log_info
from .{{cookiecutter.project_slug}} import {{ cookiecutter.__project_name_pascal_case }}InBackground


def {{ cookiecutter.project_slug }}_in_background(bv: BinaryView):
    background_task = {{ cookiecutter.__project_name_pascal_case }}InBackground(bv, "{{ cookiecutter.plugin_name }} - {{ cookiecutter.description }}")
    background_task.start()

# Register as a plugin command
log_info(f"Registering {PLUGIN_NAME!r} - {PLUGIN_DESCRIPTION!r}")

# TODO: Change the command name (if needed)
# For tree-like (nested) commands, use 'Folder\\Name' format
PluginCommand.register(
    PLUGIN_NAME+"\\{{ cookiecutter.description }}",
    "{{ cookiecutter.long_description }}",
    {{ cookiecutter.project_slug }}_in_background,
)
log_info(f"{PLUGIN_NAME!r} - {PLUGIN_DESCRIPTION!r} registered")

{% elif cookiecutter.plugin_type == 'binaryview' %}
from binaryninja import Architecture, BinaryView
from .{{cookiecutter.project_slug}} import {{ cookiecutter.__project_name_pascal_case }}View


{{ cookiecutter.__project_name_pascal_case }}View.register()
{% elif cookiecutter.plugin_type == 'ui' %}
import binaryninja


if binaryninja.core_ui_enabled():
    # MODE: GUI
    from binaryninjaui import ViewType
    from .{{cookiecutter.project_slug}} import {{ cookiecutter.__project_name_pascal_case }}ViewType
    ViewType.registerViewType({{ cookiecutter.__project_name_pascal_case }}ViewType())
else:
    # MODE: headless
    pass
{% elif cookiecutter.plugin_type == 'architecture' %}
from .{{cookiecutter.project_slug}} import {{ cookiecutter.__project_name_pascal_case }}
{{ cookiecutter.__project_name_pascal_case }}.register()

from .{{cookiecutter.project_slug}}view import {{ cookiecutter.__project_name_pascal_case }}View
{{ cookiecutter.__project_name_pascal_case }}View.register()
{% elif cookiecutter.plugin_type == 'core' %}
# TODO: Not implemented yet
{% endif %}