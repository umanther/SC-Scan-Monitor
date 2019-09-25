"""Configuration file management functions.

This file contains functions to manage the creation and verification of
configuration files used in SecurityCenter programs.

This file can also be run standalone to generate an example configuration file.

functions:

    create_blank_config_file() -> configparser.ConfigParser:
        Generate and return an example configuration file object
        as a ConfigParser object

    validate_config_file(file: str = 'config.ini') -> (configparser.ConfigParser, Exception):
        Reads and validates the file provided to be valid config, containing all required sections.
        Returns a ConfigParser object and any exception errors

    read_config_file(file: str = 'config.ini') -> configparser.ConfigParser:
        Reads provided file, returning a ConfigParser object.

    save_config_file(config: configparser.ConfigParser, file: str = 'config.ini'):
        Writes the provided ConfigParser object to a file.

error class:
    InvalidConfigurationFile
        Raised for a failed configuration file validation

"""
import configparser


def create_blank_config_file() -> configparser.ConfigParser:
    """Creates and returns a default ini file in a ConfigParser object"""
    config = configparser.ConfigParser(allow_no_value=True)
    xform = config.optionxform
    config.optionxform = str
    config['SecurityCenter'] = {"# Do not include http:// or https:// with 'hostname'": None}
    config.optionxform = xform
    config['SecurityCenter']['hostname'] = 'serveraddress.com'
    config['User'] = {'username': 'username'}
    xform = config.optionxform
    config.optionxform = str
    config['User']["# Valid password keys are 'password' and 'password64'"] = None
    config['User'][
        "# 'password64' is a Base64 encoded password and will be used over 'password' if both are present"] = None
    config.optionxform = xform
    config['User']['password'] = 'password'
    return config


def save_config_file(config: configparser.ConfigParser, file: str = 'config.ini'):
    """Saves passed ConfigParser object to file location"""
    if not isinstance(config, configparser.ConfigParser):
        raise TypeError("ConfigParser type not passed to save_config_file")

    try:
        with open(file, 'w') as config_file:
            config.write(config_file)
    except OSError as err:
        raise OSError("File Error: {0}".format(err))
    except TypeError as err:
        raise TypeError("Invalid Parameter: {0}".format(err))


def read_config_file(file: str = 'config.ini') -> configparser.ConfigParser:
    """Attempts to read passed config.ini file and return the results in a ConfigParser object"""
    config = configparser.ConfigParser()

    try:
        config.read(file)
    except Exception as err:
        print(err)

    return config


def validate_config_file(file: str = 'config.ini') -> (configparser.ConfigParser, Exception):
    config = read_config_file(file)

    config_to_lower = {}
    for items in config:
        config_to_lower[items.lower()] = items

    if 'securitycenter' not in config_to_lower:
        return None, InvalidConfigurationFile("[SecurityCenter] section not found")
    if 'user' not in config_to_lower:
        return None, InvalidConfigurationFile("[User] section not found")

    if 'hostname' not in config[config_to_lower['securitycenter']]:
        return None, InvalidConfigurationFile("hostname parameter not found")

    if 'username' not in config[config_to_lower['user']]:
        return None, InvalidConfigurationFile("username parameter not found")
    if 'password' not in config[config_to_lower['user']] and 'password64' not in config[config_to_lower['user']]:
        return None, InvalidConfigurationFile("password parameter not found")

    return config, None


# exception classes
class Error(Exception):
    """Base class for config exceptions."""

    def __init__(self, msg=''):
        self.message = msg
        Exception.__init__(self, msg)

    def __repr__(self):
        return self.message

    __str__ = __repr__


class InvalidConfigurationFile(Error):
    """Exception for an invalid configuration file"""

    def __init__(self, msg=''):
        super(InvalidConfigurationFile, self).__init__('Invalid Configuration File: {}'.format(msg))


class UnableToCreateFile(Error):

    def __init__(self, msg=''):
        super(UnableToCreateFile, self).__init__('Unable to Create File: {}'.format(msg))


if __name__ == "__main__":

    file_name = "config.ini"
    print('Generating default example configuration file ...')
    try:
        save_config_file(config=create_blank_config_file(), file=file_name)
    except Exception as err:
        raise UnableToCreateFile(err)
    print("File created: {}".format(file_name))
