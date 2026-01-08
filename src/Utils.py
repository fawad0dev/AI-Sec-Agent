import subprocess
import sys
import platform
import psutil

# Windows registry module is only available on Windows
try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False

# Cache the OS type to avoid repeated system calls
OS_TYPE = platform.system()

class Utils:
    def __init__(self):
        """Initialize Utils with cached OS type."""
        self.os_type = OS_TYPE
    
    def get_system_info(self):
        """
        Get system information.
        os, version, ram, cpu, gpu, isConnectedToInternet and more 
        Returns:
            dict: System information
        """
        try:
            system_info = {
                "os": platform.system(),
                "os_version": platform.version(),
                "platform": platform.platform(),
                "processor": platform.processor(),
                "cpu_count": psutil.cpu_count(logical=True),
                "ram_total_gb": round(psutil.virtual_memory().total / (1024 ** 3), 2),
                "ram_available_gb": round(psutil.virtual_memory().available / (1024 ** 3), 2),
                "is_connected_to_internet": self.check_internet_connection()
            }
            return system_info
        except Exception as e:
            return {"error": str(e)}
    def check_internet_connection(self):
        """
        Check if the system is connected to the internet.

        Returns:
            bool: True if connected to internet, False otherwise
        """
        try:
            result = subprocess.run(['ping', '-n' if platform.system() == 'Windows' else '-c', '1', '8.8.8.8'], 
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, OSError):
            return False

    def read_file(self, file_path, nooflines=None, encoding='utf-8'):
        """
        Read and return text content from a file.

        Args:
            file_path (str): Path to the file
            nooflines (int, optional): Number of lines to read from the end. If None, reads entire file.

        Returns:
            str: Content of the file
        """
        try:
            with open(file_path, 'r', encoding=encoding) as file:
                if nooflines is None:
                    return file.read()
                else:
                    lines = file.readlines()
                    return ''.join(lines[-nooflines:])
        except FileNotFoundError:
            return (f"Error: File '{file_path}' not found.")
        except Exception as e:
            return (f"Error reading file: {e}")
    def write_file(self, file_path, content, encoding='utf-8'):
        """
        Write text content to a file.

        Args:
            file_path (str): Path to the file
            content (str): Text content to write to the file
        """
        try:
            with open(file_path, 'w', encoding=encoding) as file:
                file.write(content)
            return "Written Successfully"
        except Exception as e:
            return (f"Error writing to file: {e}")
    def append_file(self, file_path, content, encoding='utf-8'):
        """
        Append text content to a file.

        Args:
            file_path (str): Path to the file
            content (str): Text content to append to the file
        """
        try:
            with open(file_path, 'a', encoding=encoding) as file:
                file.write(content)
            return "Appended Successfully"
        except Exception as e:
            return (f"Error appending to file: {e}")
    def is_admin(self):
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except (AttributeError, OSError):
            return False
    def run_terminal_command(self, command, allowed=False):
        """
        Execute a shell command and return its output.
        Automatically detects OS type before executing commands.

        Args:
            command (str): Shell command to execute
            allowed (bool): Whether command execution is allowed
        
        Returns:
            str: Command output or error message
        """
        if not allowed:
            return "Cancelled By User"
        
        if not command or not isinstance(command, str):
            return "Error: Invalid command"
        
        # Basic validation - prevent obviously dangerous patterns
        dangerous_patterns = ['rm -rf /', 'del /f /s /q', 'format ', 'mkfs', ':(){:|:&};:']
        for pattern in dangerous_patterns:
            if pattern in command.lower():
                return f"Error: Command blocked for security reasons"
        
        try:
            # Use timeout to prevent hanging
            result = subprocess.run(
                command, 
                shell=True, 
                check=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True,
                timeout=30
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            return f"Error: Command timed out after 30 seconds"
        except subprocess.CalledProcessError as e:
            return f"Error executing command '{command}' on {self.os_type}: {e.stderr}"
        except Exception as e:
            return f"Error: {str(e)}"
    def read_Registry(self, key, sub_key, reserved=0, access=None):
        """
        Read Windows Registry key values.

        Args:
            key: Root registry key (e.g., winreg.HKEY_LOCAL_MACHINE)
            sub_key (str): Subkey path
            reserved (int): Reserved parameter (default is 0)
            access (int): Access rights (default is winreg.KEY_READ)

        Returns:
            list: List of registry values in "name: value" format
        """
        if not HAS_WINREG:
            return ["Error: winreg module not available on this platform."]
        
        if access is None:
            access = winreg.KEY_READ
        
        values = []
        try:
            with winreg.OpenKey(key, sub_key, reserved, access) as reg_key:
                i = 0
                while True:
                    try:
                        value = winreg.EnumValue(reg_key, i)
                        values.append(f"{value[0]}: {value[1]}")
                        i += 1
                    except OSError:
                        break
        except FileNotFoundError:
            values.append(f"Error: Registry key '{sub_key}' not found.")
        except Exception as e:
            values.append(f"Error reading registry: {e}")
        
        return values
    def write_Registry(self, key, sub_key, value_name, value, value_type=None):
        """
        Write a value to the Windows Registry.

        Args:
            key: Root registry key (e.g., winreg.HKEY_LOCAL_MACHINE)
            sub_key (str): Subkey path
            value_name (str): Name of the registry value
            value: Value to set
            value_type: Type of the registry value (default is winreg.REG_SZ)

        Returns:
            str: Success or error message
        """
        if not HAS_WINREG:
            return "Error: winreg module not available on this platform."
        
        if value_type is None:
            value_type = winreg.REG_SZ
        
        try:
            with winreg.CreateKey(key, sub_key) as reg_key:
                winreg.SetValueEx(reg_key, value_name, 0, value_type, value)
            return "Registry value written successfully."
        except Exception as e:
            return f"Error writing to registry: {e}"