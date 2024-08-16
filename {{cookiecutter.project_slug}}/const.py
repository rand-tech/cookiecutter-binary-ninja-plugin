PLUGIN_NAME = "{{ cookiecutter.plugin_name }}"
PLUGIN_DESCRIPTION = "{{ cookiecutter.description }}"
PLUGIN_VERSION = "{{ cookiecutter.version }}"
PLUGIN_AUTHOR = "{{ cookiecutter.author_name }}"
{% if cookiecutter.plugin_type == 'architecture' %}
ADDRESS_SIZE = 2 # TODO
ARCH_VIEW_NAME = "{{ cookiecutter.plugin_name|lower }}"
ARCH_NAME = "{{ cookiecutter.plugin_name|lower }}:{{ cookiecutter.plugin_name|lower }}"
{% endif %}