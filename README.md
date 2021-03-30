# process-hiders
Hides processes from the windows task manager using IAT hooking - hooks the function NtQuerySystemInformation.
Inspired by [this](https://edgix.co/task-manager/) great article.
Injects the code that performs the IAT hooking to the remote proecess using several methods:
- DLL Injection:
    - ClassicInjector - the classic DLL injector via CreateRemoteThread and LoadLibrary.
    - GlobalHookInjector - injects the DLL via SetWindowsHookEx to all existing threads running in the same desktop.
- Direct Code Injection:
    - Injects the code directly to the remote process memory using WriteProcessMemory and executes it using CreateRemoteThread.
