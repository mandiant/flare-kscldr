# Kernel Shellcode Loader

FLARE kernel shellcode loader. For discussion and example usage, see the blog:
[Loading Kernel Shellcode](https://www.fireeye.com/blog/threat-research/2018/04/loading-kernel-shellcode.html).

# Build

## Building the Driver
1. Open a WDK build prompt
2. Run `ez.cmd` to build and sign the driver and build the user-space app
3. Output files will be in the `bin` directory

The user-space executable will install the driver if it is not already
installed.

## Building the User-Space Application Without msvcrt (optional)
1. Open a Visual Studio build prompt
2. Change to this directory
3. Type `rc.exe resource.rc`
4. Type `cl.exe /Fekscldr.exe /I..\inc kscldr_u.c resource.res`

# Target Setup
One-time setup:
1. Run `bcdedit /set testsigning on`
2. Set up kernel debugging (likely entails `bcdedit /set debug on`).
3. Not essential, but if you want to see debug output, be sure to adjust the
   following setting:
    ```
    [HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter]
    "DEFAULT"=dword:00000008
    ```
    The setting is literally named `DEFAULT` (as opposed to the `(Default)`
    value that is present under all registry keys). For details, see:
    [Getting DbgPrint Output To Appear In Vista and Later](http://www.osronline.com/article.cfm?article=295)
4. Reboot.
5. Copy the user-space executable `kscldr.exe` to the target machine. It will
   install the driver when you run it.

## Optional Target Setup
Sure, you can install the driver manually if you really want to:

```
sc create kscldr type= kernel start= demand binPath= %CD%\kscldr.sys
```

The spaces after the equals are important, alas.

# Running It
1. Open either SysInternals' `DbgView` or your kernel debugger
2. Run `kscldr.exe your_kernel_shellcode.bin`

If compiled with `CFG_EN_ENFORCE_BREAKPOINT` disabled (see `inc\config.h`),
then the tool requires an additional requirement indicating whether to issue a
kernel breakpoint prior to entering the shellcode.
