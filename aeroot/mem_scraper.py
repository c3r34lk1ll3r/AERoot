"""
Analyze the memory in order to find the offset
"""
import sys
from aeroot.avd import Avd, AVDError, AmbiguousProcessNameError
from aeroot.gdb import GdbHelper, GdbError
import yaml
import subprocess
from ppadb.client import Client as AdbClient
from aeroot.util import debug, info
from pathlib import Path



from vmlinux_to_elf.core.vmlinuz_decompressor import obtain_raw_kernel_from_file
from vmlinux_to_elf.core.architecture_detecter import ArchitectureGuessError
from vmlinux_to_elf.core.kallsyms import KallsymsFinder

def search_kernel_address(configuration, gdb, base, end):
    debug("Retrieving kernel base address from memory")
    _KERNEL_BASE_CMD = (
        "python",
        "range_start = {}",
        "range_stop = {}",
        "found = False",
        "for addr in range(range_start, range_stop, 0x1000000):",
        "   if found: break",
        "   try:",
        "       gdb.execute('x/a %d'%addr, to_string=True)",
        "       k_addr = addr",
        "       c_addr = addr - 0x100000",
        "       while c_addr > addr - 0x1000000:",
        "           try:",
        "               gdb.execute('x/a %d'%c_addr, to_string=True)",
        "               k_addr = c_addr",
        "               c_addr -= 0x100000",
        "           except gdb.MemoryError:",
        "               print('#%d'%k_addr)",
        "               found = True",
        "               break",
        "   except gdb.MemoryError:",
        "       pass",
        "end")
    configuration['mem_range'] ={'begin':base,'end':end}
    cmd = "\n".join(_KERNEL_BASE_CMD).format(
        base, end
    )

    try:
        result = gdb.execute(cmd)

        if len(result) == 0:
            print("Can't find kernel base address. Updating gdbstub...")
            gdb.update()
            result = gdb.execute(cmd)
    except GdbError as err:
        raise AVDError(err)

    if len(result) == 0:
        raise AVDError("Can't retrieve kernel base from memory")

    _base_address = int(
        result[0].get("payload").replace("#", "").replace("\\n", "")
    )
    info("Base address kernel: "+hex(_base_address))
    return _base_address


def search_for_tasklist(offset,gdb,init_task):
    task_matcher = (
        "python",
        "ps = 8", # POINTER SIZE
        "index = 0", 
        "init_task = {}",
        "comm = {}",
        "mem = gdb.selected_inferior().read_memory(init_task, 8192)",
        "while index < 8192:",
        "   test_addr = int.from_bytes(bytes(mem[index : index+ps]), 'little')",
        "   index+=ps",
# we can skip if it is not a pointer to a memory area. Also, this can't be found it the kernel segment
        "   if test_addr < 0xffff000000000000 or test_addr > 0xffffffff00000000:",
        "       continue",
        "   try:",
        "       next_task = gdb.selected_inferior().read_memory(test_addr - (index-ps) + comm, 16)",
        "       name = bytes(next_task)",
        "       if name[0] == 0x00:",
        "           continue",
        "       if name.isascii() and b\"init\" in name.strip():",
        "           print(\"Found at \"+hex(test_addr))",
        "           print(name)",
        "           tasks = index-ps",
        "           print(\"#\"+str(tasks))",
        "           break",
        "   except gdb.MemoryError:",
        "       pass",
        "end")
    cmd = "\n".join(task_matcher).format(init_task, offset['comm'])
    result = gdb.execute(cmd)
    if len(result) == 0 or len(result) > 1:
        print("ERROR")
        return
    offset_tasks = int(result[0]['payload'][1:])
    debug("Retrieved TASKS offset:"+str(offset_tasks))
    return offset_tasks

# Searching for PID    
def search_for_pid(offset, gdb, init_task):
    pid_matcher = (
    "python",
    "init_task = {}",
    "tasks = {}",
    "def read_uint32_t(address):",
    "   uint32_t = gdb.lookup_type('unsigned int').pointer()",
    "   return address.cast(uint32_t).dereference()",
    "def read_pointer(address):",
    "   void_t = gdb.lookup_type('void').pointer().pointer()",
    "   return address.cast(void_t).dereference()",
    "tentative_pid = 0x0",
    "while tentative_pid < 8192:",
    "   c_task = gdb.Value(init_task)", ## INIT_TASK
    "   pid = int(read_uint32_t(c_task+tentative_pid))",
    "   if pid != 0:",
    "       tentative_pid +=4",
    "       continue",
    "   index = 1",
    "   while index < 5:",
    "       address = read_pointer(c_task + tasks) # Read next process",
    "       c_task = address - tasks # Set as c_task ",
    "       pid = int(read_uint32_t(c_task+tentative_pid))",
    "       if pid != index: # first process has PID = 1, second =2 ecc",
    "           break",
    "       index +=1",
    "   if index == 5: # After 5 correct PID this is a good pattern",
    "       pid = tentative_pid",
    "       print(\"#\"+str(pid))",
    "       break",
    "   tentative_pid +=4",
    "end")
    cmd = "\n".join(pid_matcher).format(init_task, offset['tasklist'])
    result = gdb.execute(cmd)
    offset_pid = int(result[0]['payload'][1:])
    debug("Retrieved PID offset:"+str(offset_pid))
    return offset_pid

# Search for parent
def search_for_parent(offset,gdb, init_task):
    parent_matcher = (
    "python",
    "def read_pointer(address):",
    "   void_t = gdb.lookup_type('void').pointer().pointer()",
    "   return address.cast(void_t).dereference()",
    "t_parent = 0",
    "init_task = {}",
    "tasks = {}",
    "c_task = gdb.Value(init_task)",
    "address = read_pointer(c_task + tasks) # Reading next process",
    "n_task = address - tasks",
    "## Again, the point is that the parent pointer in the next process is the init_task process",
    "while t_parent < 8192:",
    "   parent = read_pointer(n_task+t_parent) ## Searching in the memory",
    "   if parent == c_task:",
    "       print(\"#\"+str(t_parent))",
    "       break",
    "   t_parent+=4",
    "end")
    cmd = "\n".join(parent_matcher).format(init_task, offset['tasklist'])
    result = gdb.execute(cmd)
    offset_parent = int(result[0]['payload'][1:])
    debug("Retrieved PARENT offset:"+str(offset_parent))
    return offset_parent

# Search for creds structure
def search_for_creds(offset, gdb, init_task):
    creds_matcher = (
    "python",
    "import struct",
    "index = 0",
    "init_task = {}",
    "mem = gdb.selected_inferior().read_memory(init_task, 8192)",
    "addr_dict = {{}}",
    "while index < 8192:",
    "   test_addr = int.from_bytes(bytes(mem[index : index+ps]), 'little') # Searching for every pointer",
    "   index+=ps",
    "   if test_addr < 0xffffffff00000000:",
    "       continue",
    "   try:",
    "       mem2 = gdb.selected_inferior().read_memory(test_addr, 184) # Read the memory pointed",
    "       inx = 0",
    "       while inx < 176:",
    "           usage = struct.unpack('<Q',mem2[inx:inx+8])[0]",
    "           if usage == 0x1FFFFFFFFFF: # CAP_FULL_SET",
    "               if hex(test_addr) not in addr_dict:",
    "                   addr_dict[hex(test_addr)] = [1, index]",
    "               else:",
    "                   addr_dict[hex(test_addr)][0] += 1 ",
    "           inx+=8",
    "   except gdb.MemoryError:",
    "       pass # Memory error ",
    "for i in addr_dict:",
    "   if addr_dict[i][0] == 6: # 6 because creds are stored in two point, real_creds and creds, we need two offset?",
    "       index = 0",
    "       print(\"#\"+str(i))",
    "       print(\"#\"+str(addr_dict[i][1]))",
    "end")
    cmd = "\n".join(creds_matcher).format(init_task)
    result = gdb.execute(cmd)
    offset_init = int(result[0]['payload'][1:], 16) 
    offset_cred = int(result[1]['payload'][1:])
    debug("Retrieved CRED offset:"+str(offset_cred))
    debug("Retrieved INITCREDS offset:"+str(offset_init))
    return offset_init, offset_cred

def forensic(options):
        avd = Avd(options.device, options.host, options.port)
        device = AdbClient(host=options.host, port=options.port).device(options.device)
        ## We can try with kallsym-finder
        uname=device.shell("uname -rm").replace(" ", "_").strip()
        arch = device.shell("uname -m").strip()
        ## Sizeof
        if arch == "x86_64":
            sizeof = {'address':8, 'enforce':1}
        if arch == "i686":
            sizeof = {'address': 8, 'enforce':1}
            arch = "x86_64"
        configuration = {'name':uname, 'arch':arch, 'sizeof':sizeof}
        off = {}
        with open(options.mem_scrape, 'rb') as kernel_bin:
            try:
                kallsyms = KallsymsFinder(obtain_raw_kernel_from_file(kernel_bin.read()))
        
            except ArchitectureGuessError:
                exit('[!] The architecture of your kernel could not be guessed ' +
                'successfully. Please specify the --bit-size argument manually ' +
                '(use --help for its precise specification).')
            index = 0
            for symbol_name in kallsyms.symbol_names:
                if 'init_task' == symbol_name[1:]:
                    init_task= kallsyms.kernel_addresses[index]
                elif '_text' == symbol_name[1:]:
                    s_text = kallsyms.kernel_addresses[index]
                elif 'selinux_state' == symbol_name[1:]:
                    selinux = kallsyms.kernel_addresses[index]
                index +=1
        off['swapper'] = init_task - s_text
        off['selinux'] = selinux   - s_text

        offset = {}
        configuration['offset'] = off
        gdb = GdbHelper(device=avd.device, arch=arch)
        try:
            gdb.start()
    
            if not gdb.has_python():
                raise GdbPythonSupportError
        except GdbError as err:
            raise AVDError(err)
        
        # There are for sure better way to do this
        base = s_text & 0xFFFFFFFF00000000
        end = 0xFFFFFFFFFFFFFFFF
        _base_address = search_kernel_address(configuration, gdb, base, end)
        
        # Search for swapper string
        swapper=off['swapper']
        init_task = swapper + _base_address
        debug("Init_task address: "+hex(init_task))
        line = "{}, +8192, 's','w','a','p','p','e','r'".format(init_task)
        addr = gdb.find(line)
        ## TO CHECK THAT IF JUST ONE LINE
        if len(addr) == 0 or len(addr) > 1:
            info("COMM not found, error")
            return
        offset['comm'] = int(addr[0]) - init_task
        debug("Retrieved COMM offset "+str(offset['comm']))

        ## Search for tasklist
        offset['tasklist'] = search_for_tasklist(offset, gdb, init_task)
        
        offset['pid'] = search_for_pid(offset, gdb, init_task)

        offset['parent'] = search_for_parent(offset, gdb, init_task)

        offset_init, offset_cred = search_for_creds(offset, gdb, init_task)
        
        offset['creds'] = offset_cred
        offset['init']  = offset_init - _base_address

        configuration['task'] = {'offset':offset}
        root_path = Path(Path(__file__).resolve().parent.parent, "config", "kernel", uname+'.yaml')

        yaml.dump(configuration, open(root_path, 'w'))
        info("Yaml file saved at "+str(root_path))
