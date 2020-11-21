import ctypes

def get_constants():
    return {
    'USER32': ctypes.windll.user32,  #Globals
    'MessageBoxW': ctypes.windll.user32.MessageBoxW,
    'MB_OK': 0x0
    }