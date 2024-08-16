""" A {{ cookiecutter.plugin_type }} plugin for Binary Ninja generated by cookiecutter-binary-ninja-plugin! """
{% if cookiecutter.plugin_type == 'architecture' %}
from binaryninja.architecture import Architecture
from binaryninja.binaryview import BinaryView

from .const import ARCH_NAME, ARCH_VIEW_NAME


class {{ cookiecutter.__project_name_pascal_case }}View(BinaryView):
    name = ARCH_VIEW_NAME
    long_name = ARCH_VIEW_NAME

    @classmethod
    def is_valid_for_data(self, data: BinaryView):
        sample = data.read(0, 0x100)
        raise NotImplementedError()
        return sample.startswith(b"TODO: Change the magic bytes")  # TODO: Change the magic bytes

    def __init__(self, data: BinaryView):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.platform = Architecture[ARCH_NAME].standalone_platform
        self.data = data

    def init(self):
        self.arch = Architecture[ARCH_NAME]
        raise NotImplementedError()
        return True

    def perform_is_executable(self) -> bool:
        return True

    def perform_get_entry_point(self) -> int:
        raise NotImplementedError()

    def perform_get_address_size(self) -> int:
        raise NotImplementedError()
{% endif %}