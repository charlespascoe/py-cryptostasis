import sys

OFF = 0
INFO = 1
VERBOSE = 2
DEBUG = 3

level = OFF

def log(log_level, line_prefix=None, message='', line_ending='\n'):
    if level < log_level:
        return

    message = str(message)

    if line_prefix is not None:
        message = '\n'.join([line_prefix + line for line in message.split('\n')])

    sys.stderr.write(message)
    sys.stderr.write(line_ending)
    sys.stderr.flush()


def info(message='', line_ending='\n'):
    log(INFO, '[INFO] ', message, line_ending)


def verbose(message='', line_ending='\n'):
    log(VERBOSE, '[VERBOSE] ', message, line_ending)


def debug(message='', line_ending='\n'):
    log(DEBUG, '[DEBUG] ', message, line_ending)

