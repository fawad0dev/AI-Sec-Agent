import subprocess
import winreg
class Utils:
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

    def run_shell_command(self, command, allowed=False):
        """
        Execute a shell command and return its output.

        Args:
            command (str): Shell command to execute
        """
        if not allowed:
            return "Cancelled By User"
        try:
            result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            return f"Error executing command '{command}': {e.stderr}"
    def read_Registry(self, key, value_name):
        """
        Read a value from the Windows Registry.

        Args:
            key (str): Registry key path
            value_name (str): Name of the value to read
        Returns:
            str: Value from the registry
        """
        try:
            registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_READ)
            value, regtype = winreg.QueryValueEx(registry_key, value_name)
            winreg.CloseKey(registry_key)
            return value
        except Exception as e:
            return f"Error reading registry: {e}"