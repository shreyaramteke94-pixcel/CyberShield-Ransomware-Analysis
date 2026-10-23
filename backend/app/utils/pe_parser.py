from pathlib import Path

import pefile


class PEParser:
    """
    Extract information from Windows PE files safely.
    """

    @staticmethod
    def parse(file_path: Path):

        try:
            pe = pefile.PE(str(file_path))

            imports = {}

            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
                    dll = (
                        entry.dll.decode(errors="ignore")
                        if hasattr(entry, "dll") and entry.dll
                        else "unknown"
                    )

                    functions = []

                    for imp in getattr(entry, "imports", []):
                        if getattr(imp, "name", None):
                            functions.append(
                                imp.name.decode(errors="ignore")
                            )

                    imports[dll] = functions

            sections = []

            for section in getattr(pe, "sections", []):
                sec_name = (
                    section.Name.decode(errors="ignore").strip("\x00")
                    if hasattr(section, "Name") and section.Name
                    else ""
                )
                sec_vsize = getattr(section, "Misc_VirtualSize", 0)
                sec_rawsize = getattr(section, "SizeOfRawData", 0)
                sec_entropy = (
                    round(section.get_entropy(), 4)
                    if hasattr(section, "get_entropy")
                    else 0.0
                )

                sections.append({
                    "name": sec_name,
                    "virtual_size": sec_vsize,
                    "raw_size": sec_rawsize,
                    "entropy": sec_entropy,
                })

            file_header = getattr(pe, "FILE_HEADER", None)
            optional_header = getattr(pe, "OPTIONAL_HEADER", None)

            machine = getattr(file_header, "Machine", 0) if file_header else 0
            number_of_sections = (
                getattr(file_header, "NumberOfSections", 0)
                if file_header
                else len(sections)
            )
            entry_point = (
                getattr(optional_header, "AddressOfEntryPoint", 0)
                if optional_header
                else 0
            )
            image_base = (
                getattr(optional_header, "ImageBase", 0)
                if optional_header
                else 0
            )

            return {
                "machine": hex(machine),
                "number_of_sections": number_of_sections,
                "entry_point": hex(entry_point),
                "image_base": hex(image_base),
                "imports": imports,
                "sections": sections,
            }

        except Exception:
            return None
