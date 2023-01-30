## Purpose

kvardump is mainly used for printing variables in the kernel in real time. It can print complex data structures such as nested structures, arrays, etc.

## Highlight

Tools like gdb or crash can be used to print kernel variables, but these tools require a complete vmlinux file.

A complete vmlinux is not usually installed by default, and is too large for easy transfer.

kvardump read type information from BTF. Higher version kernels support BTF, so that kvardump can be used directly without any preparation.

If BTF is not enabled, a BTF file can be generated based on vmlinux. The generated BTF file is only 4MB, which is convenient for transfer.

## Preparation

Check whether BTF is enabled:
```bash
# If this file exists, BTF is already enabled and no additional processing is required.
ls /sys/kernel/btf/vmlinux
```

If BTF is not enabled, you can generate a BTF file like this:
```bash
pahole -J vmlinux
objcopy --dump-section .BTF=vmlinux.btf vmlinux 
```

Copy the generated `vmlinux.btf` to the environment to be debugged, and specify the parameter `-t` when calling kvardump.

## Usage

If `/sys/kernel/btf/vmlinux` does not exist, `-t` must be specified.

A C language evaluation expression can be passed in, which supports `.`, `->`, `[]`, `()`, `*`, and typecast.

**Note: Since the variable information is usually not included in BTF, the variable type must be specified in the expression through typecast.**

For example:

```bash
./kvardump.py 'init_net' # Fail
./kvardump.py '(struct net) init_net' # OK
./kvardump.py '*(struct net_device*) 0x0xffff8d4260214000' # OK'
```

kvardump reads variables in the kernel by default, but `-p` can be specified to read process variables.

To read process variables, the BTF file path must be specified using `-t`. The BTF file generation method for processes is the same as that for the kernel.

The specific usage can be seen in `./kvardump -h`.

You can also use `python -i kvardump.py` to enter the interactive python to call the utility functions provided by kvardump.

Type `print(dumper.HELP)` in the interactive python to see help information.
