import inspect
import logging

OKBLUE = '\033[94m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'

def log(level, message):
    func = inspect.currentframe().f_back.f_code
    logging.log(level, "%18s:%3i: %15s:  %s " % (
                func.co_filename.split("/")[-1],
                func.co_firstlineno,
                func.co_name,
                message,))

def log_error(err_msg):
	print(FAIL + BOLD + "ERROR: " + ENDC + err_msg)

def log_error2(error_prefix, err_msg):
	print(FAIL + BOLD + error_prefix + ": " + ENDC + err_msg)

def log_success(scs_msg):
	print(OKGREEN + BOLD + "OK: " + ENDC + scs_msg)

def log_info(info_msg):
	print(OKBLUE + BOLD + "INFO: " + ENDC + info_msg)

