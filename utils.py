from filelock import FileLock

# Don't want to name this anything close to the wallet filename because the
# user may have to manually delete the lock at some point.
LOCKFILE_NAME = "LOCK"

# disable the filelock timeout by setting a negative value
lock = FileLock(LOCKFILE_NAME, timeout=-1)

def lock_wallet(func):
    """
    Function decorator for locking the file.
    """
    def wrapper(*args, **kwargs):
        with lock:
            result = func(*args, **kwargs)
        return result
    return wrapper
