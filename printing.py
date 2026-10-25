import os
import shutil
import subprocess

try:
    import win32con
    import win32print
except ImportError:
    win32con = None
    win32print = None


def get_sumatra_path():
    configured_path = os.environ.get('SUMATRA_PDF_PATH')
    candidates = [
        configured_path,
        os.path.join(os.environ.get('LOCALAPPDATA', ''), 'SumatraPDF', 'SumatraPDF.exe'),
        os.path.join(os.environ.get('PROGRAMFILES', ''), 'SumatraPDF', 'SumatraPDF.exe'),
        os.path.join(os.environ.get('PROGRAMFILES(X86)', ''), 'SumatraPDF', 'SumatraPDF.exe'),
        shutil.which('SumatraPDF.exe'),
    ]
    return next((path for path in candidates if path and os.path.isfile(path)), None)


def send_to_printer(filepath, paper_size='A4', duplex=False, copies=1, print_type='Black & White'):
    try:
        sumatra_path = get_sumatra_path()
        if not sumatra_path:
            print('SumatraPDF not found; install it or set SUMATRA_PDF_PATH.')
            return False

        settings = [f'paper={paper_size}', 'fit', f'{copies}x']
        settings.append('color' if print_type == 'Color' else 'monochrome')
        if duplex:
            if win32print is None or win32con is None:
                print('Duplex printing requires Windows printer support.')
                return False
            printer_name = win32print.GetDefaultPrinter()
            printer_handle = win32print.OpenPrinter(printer_name)
            try:
                printer_info = win32print.GetPrinter(printer_handle, 2)
                supports_duplex = win32print.DeviceCapabilities(
                    printer_name,
                    printer_info['pPortName'],
                    win32con.DC_DUPLEX,
                )
            finally:
                win32print.ClosePrinter(printer_handle)
            if not supports_duplex:
                print('Selected printer does not support automatic duplex printing.')
                return False
            settings.append('duplexlong')

        result = subprocess.run(
            [sumatra_path, '-print-to-default', '-silent', '-print-settings', ','.join(settings), filepath],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
        )
        if result.returncode != 0:
            print(f"SumatraPDF print failed with exit code {result.returncode}: {result.stderr.strip()}")
            return False
        return True
    except Exception as error:
        print(f"Printing Error: {error}")
        return False
