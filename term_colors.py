class color:

    @staticmethod
    def get(*colors) -> str:
        return '\033[' + ";".join(colors) + 'm'

    END = '0'
    BRIGHT = '1'
    ITALIC = '3'
    UNDERLINE = '4'
    BLINK_SLOW = '5'
    BLINK_RAPID = '6'
    INVERSE_VIDEO = '7'
    CROSSED_OUT = '9'
    DOUBLE_UNDERLINE = '21'
    ITALIC_OFF = '23'
    UNDERLINE_OFF = '24'
    BLINK_OFF = '25'
    INVERSE_OFF = '27'
    CROSSED_OUT_OFF = '29'
    FG_BLACK = '30'
    FG_RED = '31'
    FG_GREEN = '32'
    FG_YELLOW = '33'
    FG_BLUE = '34'
    FG_MAGENTA = '35'
    FG_CYAN = '36'
    FG_WHITE = '37'

    @staticmethod
    def FG_RGB(r: int, g: int, b: int) -> str:
        r = 255 if r > 255 else r
        g = 255 if g > 255 else g
        b = 255 if b > 255 else b
        r = 0 if r < 0 else r
        g = 0 if g < 0 else g
        b = 0 if b < 0 else b
        return f"38;2;{r};{g};{b}"

    @staticmethod
    def FG_255(c: int) -> str:
        c = 255 if c > 255 else c
        c = 0 if c < 0 else c
        return f"38;5;{c}"

    BG_BLACK = '40'
    BG_RED = '41'
    BG_GREEN = '42'
    BG_YELLOW = '43'
    BG_BLUE = '44'
    BG_MAGENTA = '45'
    BG_CYAN = '46'
    BG_WHITE = '47'

    @staticmethod
    def BG_RGB(r: int, g: int, b: int) -> str:
        r = 255 if r > 255 else r
        g = 255 if g > 255 else g
        b = 255 if b > 255 else b
        r = 0 if r < 0 else r
        g = 0 if g < 0 else g
        b = 0 if b < 0 else b
        return f"48;2;{r};{g};{b}"

    @staticmethod
    def BG_255(c: int) -> str:
        c = 255 if c > 255 else c
        c = 0 if c < 0 else c
        return f"48;5;{c}"

    FRAMED = '51'
    ENCIRCLED = '52'
    OVERLINE = '53'
    FRAMED_ENCIRCLED_OFF = '54'
    OVERLINE_OFF = '55'
    FG_BR_BLACK = '90'
    FG_BR_RED = '91'
    FG_BR_GREEN = '92'
    FG_BR_YELLOW = '93'
    FG_BR_BLUE = '94'
    FG_BR_MAGENTA = '95'
    FG_BR_CYAN = '96'
    FG_BR_WHITE = '97'
    BG_BR_BLACK = '100'
    BG_BR_RED = '101'
    BG_BR_GREEN = '102'
    BG_BR_YELLOW = '103'
    BG_BR_BLUE = '104'
    BG_BR_MAGENTA = '105'
    BG_BR_CYAN = '106'
    BG_BR_WHITE = '107'
