from slowapi import Limiter
from slowapi.util import get_remote_address

# Initialize the limiter
# Key function: get_remote_address - limits by IP
limiter = Limiter(key_func=get_remote_address)
