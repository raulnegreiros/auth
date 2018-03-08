import dredd_hooks as hooks
from token_generator import generate_token


@hooks.before_each
def auth_before_each_hook(transaction):
    auth = generate_token()
    if 'request' in transaction:
        if 'headers' in transaction['request'] and 'Authorization' in transaction['request']['headers']:
            transaction['request']['headers']['Authorization'] = auth
