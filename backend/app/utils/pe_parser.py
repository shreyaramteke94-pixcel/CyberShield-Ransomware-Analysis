import pefile
from pathlib import Path
from datetime import datetime


class PEParser:
    """
    Parses Windows Portable Executable (PE) files.
    """

    @staticmethod
    def parse(file_path: Path):
        """
        Parse PE metadata.
        Returns None if the file is not a valid PE.
        """

        try:
            pe = pefile.PE(str(file_path))

            # Detect architecture
            machine = pe.FILE_HEADER.Machine

            if machine == 0x14C:
                architecture = "x86"
            elif machine == 0x8664:
                architecture = "x64"
            else:
                architecture = hex(machine)

            # Compilation timestamp
            timestamp = datetime.utcfromtimestamp(
                pe.FILE_HEADER.TimeDateStamp
            ).isoformat()

            return {
                "architecture": architecture,
                "number_of_sections": pe.FILE_HEADER.NumberOfSections,
                "entry_point": hex(
                    pe.OPTIONAL_HEADER.AddressOfEntryPoint
                ),
                "image_base": hex(
                    pe.OPTIONAL_HEADER.ImageBase
                ),
                "timestamp": timestamp,
            }

        except Exception:
            # Not a PE file
            return None