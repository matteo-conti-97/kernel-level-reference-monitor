# kernel-level-reference-monitor
We call the root directory of the project $ROOT_DIR.

# How to build and mount kernel modules:
-To build open a shell in $ROOT_DIR and execute the cmd 'bash build'.\
-To clean open a shell in $ROOT_DIR and execute the cmd 'bash clean'.\
-To mount open a shell in $ROOT_DIR and execute the cmd 'sudo bash mount < passwd >' where passwd is the password that will be requested when attempting to reconfigure the reference monitor.\
-To unmount open a shell in $ROOT_DIR and execute the cmd 'sudo bash unmount',

# How to use:
-To switch the reference monitor state open a open a shell in $ROOT_DIR/test and execute the cmd 'sudo ./switch <state> < passwd >' the possible states are 0, 1, 2, 3 which corresponds respectively to ON, OFF, REC_ON, REC_OFF.\
-To add a protected resource (file or directories) open a shell in $ROOT_DIR/test and execute the cmd 'sudo ./insert_resource <res_path> < passwd >', reference monitor state must be REC_ON or REC_OFF (when mounted default state is REC_ON).\
-To remove a protected resource (file or directories) open a shell in $ROOT_DIR/test and execute the cmd 'sudo ./remove_resource <res_path> < passwd >', reference monitor state must be REC_ON or REC_OFF (when mounted default state is REC_ON).\
-To test if reference monitor is protecting the resources added there are multiple scripts to test all the possible write scenarios. Those scripts are 'test_open', 'test_create', 'test_truncate', 'test_rename', 'test_link', 'test_symlink', 'test_unlink', 'test_mkdir', 'test_mknod', 'test_rmdir' see the implementation for parameter details. Note that reference monitor will block operations on protected file only if state is ON or REC_ON.
