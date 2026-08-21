from pathlib import Path

import pefile


class PEParser:
    """
    Extract information from Windows PE files.
    """

    @staticmethod
    def parse(file_path: Path):

        try:
            pe = pefile.PE(str(file_path))

            imports = {}

            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:

                    dll = entry.dll.decode()

                    functions = []

                    for imp in entry.imports:
                        if imp.name:
                            functions.append(
                                imp.name.decode()
                            )

                    imports[dll] = functions

            sections = []

            for section in pe.sections:
                sections.append({
                    "name": section.Name.decode(
                        errors="ignore"
                    ).strip("\x00"),
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "entropy": round(
                        section.get_entropy(),
                        4,
                    ),
                })

            return {
                "machine": hex(pe.FILE_HEADER.Machine),
                "number_of_sections":
                    pe.FILE_HEADER.NumberOfSections,
                "entry_point":
                    hex(
                        pe.OPTIONAL_HEADER.AddressOfEntryPoint
                    ),
                "image_base":
                    hex(pe.OPTIONAL_HEADER.ImageBase),
                "imports": imports,
                "sections": sections,
            }

        except Exception:
            return None