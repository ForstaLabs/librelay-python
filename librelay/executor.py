import asyncio
import os
from concurrent.futures import ThreadPoolExecutor

_executor = None


async def run(fn, *args):
    """ Perform blocking tasks in a thread to free the event loop. """
    loop = asyncio.get_running_loop()
    global _executor
    if _executor is None:
        _executor = ThreadPoolExecutor(max_workers=os.cpu_count(),
                                       thread_name_prefix='LibRelayExecutor')
    return await loop.run_in_executor(_executor, fn, *args)
