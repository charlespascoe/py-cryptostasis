import sys

OFF = 0
INFO = 1
VERBOSE = 2
DEBUG = 3

level = OFF

log_strm = sys.stderr

def component_name(component):
    if isinstance(component, str):
        return component

    return component.__class__.__name__


def format_prefix(level_name, component):
    if (level >= DEBUG):
        return '[{} @ {}] '.format(level_name, component_name(component))
    else:
        return '[{}] '.format(level_name)


def msg(message='', line_ending='\n'):
    sys.stderr.write(message)
    sys.stderr.write(line_ending)
    sys.stderr.flush()


def log(log_level, line_prefix=None, message='', line_ending='\n'):
    if level < log_level:
        return

    message = str(message)

    if line_prefix is not None:
        message = '\n'.join([line_prefix + line for line in message.split('\n')])

    log_strm.write(message)
    log_strm.write(line_ending)
    log_strm.flush()


def info(component, message, line_ending='\n'):
    log(INFO, format_prefix('INFO', component), message, line_ending)


def verbose(component, message, line_ending='\n'):
    log(VERBOSE, format_prefix('VERBOSE', component), message, line_ending)


def debug(component, message, line_ending='\n'):
    log(DEBUG, format_prefix('DEBUG', component), message, line_ending)

def format_bytes(buff):
    hex_str = buff.hex()

    if len(hex_str) > 16:
        return '{}...'.format(hex_str[:16])

    return hex_str
