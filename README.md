# kernel-level-reference-monitor
## Description
This specification is related to a Linux Kernel Module (LKM) implementing a reference monitor for file protection. The reference monitor can be in one of the following four states:\

-OFF, meaning that its operations are currently disabled.\
-ON, meaning that its operations are currently enabled.\
-REC-ON/REC-OFF, meaning that it can be currently reconfigured (in either ON or OFF mode).\
The configuration of the reference monitor is based on a set of file system paths. Each path corresponds to a file/dir that cannot be currently opened in write mode. Hence, any attempt to write-open the path needs to return an error, independently of the user-id that attempts the open operation.\

Reconfiguring the reference monitor means that some path to be protected can be added/removed. In any case, changing the current state of the reference monitor requires that the thread that is running this operation needs to be marked with effective-user-id set to root, and additionally the reconfiguration requires in input a password that is reference-monitor specific. This means that the encrypted version of the password is maintained at the level of the reference monitor architecture for performing the required checks.\

It is up to the software designer to determine if the above states ON/OFF/REC-ON/REC-OFF can be changed via VFS API or via specific system-calls. The same is true for the services that implement each reconfiguration step (addition/deletion of paths to be checked). Together with kernel level stuff, the project should also deliver user space code/commands for invoking the system level API with correct parameters.\

In addition to the above specifics, the project should also include the realization of a file system where a single append-only file should record the following tuple of data (per line of the file) each time an attempt to write-open a protected file system path is attempted:\

-the process TGID.\
-the thread ID.\
-the user-id.\
-the effective user-id.\
-the program path-name that is currently attempting the open.\
-a cryptographic hash of the program file content.\

The the computation of the cryptographic hash and the writing of the above tuple should be carried in deferred work.

## Manual
We call the root directory of the project $ROOT_DIR.

### How to build and mount kernel modules:
-To build open a shell in $ROOT_DIR and execute the cmd 'bash build'.\
-To clean open a shell in $ROOT_DIR and execute the cmd 'bash clean'.\
-To mount open a shell in $ROOT_DIR and execute the cmd 'sudo bash mount < passwd >' where passwd is the password that will be requested when attempting to reconfigure the reference monitor.\
-To unmount open a shell in $ROOT_DIR and execute the cmd 'sudo bash unmount'.

### How to use:
-To switch the reference monitor state open a open a shell in $ROOT_DIR/test and execute the cmd 'sudo ./switch <state> < passwd >' the possible states are 0, 1, 2, 3 which corresponds respectively to ON, OFF, REC_ON, REC_OFF.\
-To add a protected resource (file or directories) open a shell in $ROOT_DIR/test and execute the cmd 'sudo ./insert_resource <res_path> < passwd >', reference monitor state must be REC_ON or REC_OFF (when mounted default state is REC_ON).\
-To remove a protected resource (file or directories) open a shell in $ROOT_DIR/test and execute the cmd 'sudo ./remove_resource <res_path> < passwd >', reference monitor state must be REC_ON or REC_OFF (when mounted default state is REC_ON).\
-To test if reference monitor is protecting the resources added there are multiple scripts to test all the possible write scenarios. Those scripts are 'test_open', 'test_create', 'test_truncate', 'test_rename', 'test_link', 'test_symlink', 'test_unlink', 'test_mkdir', 'test_mknod', 'test_rmdir' see the implementation for parameter details. Note that reference monitor will block operations on protected file only if state is ON or REC_ON.
