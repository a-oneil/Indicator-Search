import json
import jinja_partials
from starlette.templating import Jinja2Templates


class terminalColors:
    """
    Class for coloring terminal output
    """

    BLUE = "\033[36m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    ENDCOLOR = "\033[0m"


def load_config_file():
    """
    This function will load the ./config/.env file and return the config dictionary
    """
    try:
        f = open("./config/.env", "r")
        config = json.load(f)
        f.close()
        print(f"{color.BLUE}Config file loaded successfully!{color.ENDCOLOR}")
        return config
    except Exception as e:
        print(
            f"{color.RED}Error occurred while loading the file: {str(e)}{color.ENDCOLOR}"
        )


color = terminalColors()
templates = Jinja2Templates(directory="app/routers/web/templates")
jinja_partials.register_starlette_extensions(templates)
config = load_config_file()
