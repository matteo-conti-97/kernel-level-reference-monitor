import subprocess
import sys

default_passwd = "1234"

def switch_state(state, passwd):
    # Ensure the C executable is in the same directory or provide the full path
    executable = './switch_state'
    
    if(passwd is None):
        passwd = default_passwd
    
    try:
        # Run the C program with the provided parameters
        result = subprocess.run([executable] + [state, passwd], capture_output=True, text=True)
        
        # Print the output of the C program
        print("C Program Output:")
        print(result.stdout)
        
        # Print any error output (if any)
        if result.stderr:
            print("C Program Error Output:")
            print(result.stderr)
        
    except FileNotFoundError:
        print(f"Error: The executable '{executable}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

def insert_resource(res, passwd):
    # Ensure the C executable is in the same directory or provide the full path
    executable = './insert_resource'
    
    if(passwd is None):
        passwd = default_passwd
    
    try:
        # Run the C program with the provided parameters
        result = subprocess.run([executable] + ['1', res, passwd], capture_output=True, text=True)
        
        # Print the output of the C program
        print("C Program Output:")
        print(result.stdout)
        
        # Print any error output (if any)
        if result.stderr:
            print("C Program Error Output:")
            print(result.stderr)
        
    except FileNotFoundError:
        print(f"Error: The executable '{executable}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
        
def remove_resource(res, passwd):
    # Ensure the C executable is in the same directory or provide the full path
    executable = './remove_resource'
    
    if(passwd is None):
        passwd = default_passwd
    
    try:
        # Run the C program with the provided parameters
        result = subprocess.run([executable] + [res, passwd], capture_output=True, text=True)
        
        # Print the output of the C program
        print("C Program Output:")
        print(result.stdout)
        
        # Print any error output (if any)
        if result.stderr:
            print("C Program Error Output:")
            print(result.stderr)
        
    except FileNotFoundError:
        print(f"Error: The executable '{executable}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

def test_state_transistion(passwd):
    # Ensure the C executable is in the same directory or provide the full path
    executable = './test_state_transition'
    
    if(passwd is None):
        passwd = default_passwd
    
    try:
        # Run the C program with the provided parameters
        result = subprocess.run([executable] + [passwd], capture_output=True, text=True)
        
        # Print the output of the C program
        print("C Program Output:")
        print(result.stdout)
        
        # Print any error output (if any)
        if result.stderr:
            print("C Program Error Output:")
            print(result.stderr)
        
    except FileNotFoundError:
        print(f"Error: The executable '{executable}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
        
def test_insert_remove(res, passwd):
    # Ensure the C executable is in the same directory or provide the full path
    executable = './test_insert_remove'
    default_path = "/home/test_insert_remove.txt"
    
    if(passwd is None):
        passwd = default_passwd
        
    if(res is None):
        res = default_path
    
    try:
        # Run the C program with the provided parameters
        result = subprocess.run([executable] + [res, passwd], capture_output=True, text=True)
        
        # Print the output of the C program
        print("C Program Output:")
        print(result.stdout)
        
        # Print any error output (if any)
        if result.stderr:
            print("C Program Error Output:")
            print(result.stderr)
        
    except FileNotFoundError:
        print(f"Error: The executable '{executable}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
 
def test_open(res_path, protected_res_path):
    
    # Ensure the C executable is in the same directory or provide the full path
    executable = './test_open'
    
    default_res_path = '/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova.txt'
    default_protected_res_path = '/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova.txt'
    
    if(res_path is None):
        res_path = default_res_path
    
    if(protected_res_path is None):
        protected_res_path = default_protected_res_path
        
    insert_resource(default_protected_res_path, default_passwd)
    
    
    try:
        # Run the C program with the provided parameters
        result = subprocess.run([executable] + [res_path], capture_output=True, text=True)
        
        # Print the output of the C program
        print("C Program Output:")
        print(result.stdout)
        
        # Print any error output (if any)
        if result.stderr:
            print("C Program Error Output:")
            print(result.stderr)
        
    except FileNotFoundError:
        print(f"Error: The executable '{executable}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
        
    remove_resource(default_protected_res_path, default_passwd)

def test_create(res_path, protected_res_path):
        
    # Ensure the C executable is in the same directory or provide the full path
    executable = './test_create'
    
    default_res_path = "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova_dir/prova.txt"
    default_protected_res_path = "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova_dir"
    
    if(res_path is None):
        res_path = default_res_path
    
    if(protected_res_path is None):
        protected_res_path = default_protected_res_path
        
    insert_resource(default_protected_res_path, default_passwd)
    
    try:
        # Run the C program with the provided parameters
        result = subprocess.run([executable] + [res_path], capture_output=True, text=True)
        
        # Print the output of the C program
        print("C Program Output:")
        print(result.stdout)
        
        # Print any error output (if any)
        if result.stderr:
            print("C Program Error Output:")
            print(result.stderr)
        
    except FileNotFoundError:
        print(f"Error: The executable '{executable}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
        
    remove_resource(default_protected_res_path, default_passwd)

def test_mk_hardlink(link_path, res_path, protected_res_path):
    # Ensure the C executable is in the same directory or provide the full path
    executable = './test_link'
    
    default_res_path = "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova.txt"
    default_link_path = "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova_dir/test_hardlink.txt"
    default_protected_res_path = "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova_dir"
    
    if(res_path is None):
        res_path = default_res_path
        
    if(link_path is None):
        link_path = default_link_path
    
    if(protected_res_path is None):
        protected_res_path = default_link_path
        
    insert_resource(default_protected_res_path, default_passwd)
    
    try:
        # Run the C program with the provided parameters
        result = subprocess.run([executable] + [res_path, link_path], capture_output=True, text=True)
        
        # Print the output of the C program
        print("C Program Output:")
        print(result.stdout)
        
        # Print any error output (if any)
        if result.stderr:
            print("C Program Error Output:")
            print(result.stderr)
        
    except FileNotFoundError:
        print(f"Error: The executable '{executable}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
        
    remove_resource(default_protected_res_path, default_passwd)

def test_mk_symlink(link_path, res_path, protected_res_path):
    # Ensure the C executable is in the same directory or provide the full path
    executable = './test_symlink'
    
    default_res_path = "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova.txt"
    default_link_path = "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova_dir/test_symlink.txt"
    default_protected_res_path = "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova_dir"
    
    if(res_path is None):
        res_path = default_res_path
        
    if(link_path is None):
        link_path = default_link_path
    
    if(protected_res_path is None):
        protected_res_path = default_link_path
        
    insert_resource(default_protected_res_path, default_passwd)
    
    try:
        # Run the C program with the provided parameters
        result = subprocess.run([executable] + [res_path, link_path], capture_output=True, text=True)
        
        # Print the output of the C program
        print("C Program Output:")
        print(result.stdout)
        
        # Print any error output (if any)
        if result.stderr:
            print("C Program Error Output:")
            print(result.stderr)
        
    except FileNotFoundError:
        print(f"Error: The executable '{executable}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
        
    remove_resource(default_protected_res_path, default_passwd)

def test_unlink(link_path, protected_res_path):
    # Ensure the C executable is in the same directory or provide the full path
    executable = './test_unlink'
    
    default_link_path = "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova_dir/test_unlink.txt"
    default_protected_res_path = "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova_dir"
    
    if(link_path is None):
        link_path = default_link_path
    
    if(protected_res_path is None):
        protected_res_path = default_link_path
        
    insert_resource(default_protected_res_path, default_passwd)
    
    try:
        # Run the C program with the provided parameters
        result = subprocess.run([executable] + [link_path], capture_output=True, text=True)
        
        # Print the output of the C program
        print("C Program Output:")
        print(result.stdout)
        
        # Print any error output (if any)
        if result.stderr:
            print("C Program Error Output:")
            print(result.stderr)
        
    except FileNotFoundError:
        print(f"Error: The executable '{executable}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
        
    remove_resource(default_protected_res_path, default_passwd)

def test_truncate(res_path, protected_res_path):
    # Ensure the C executable is in the same directory or provide the full path
    executable = './test_truncate'
    
    default_res_path = "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova.txt"
    default_protected_res_path = "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova.txt"
    
    if(res_path is None):
        res_path = default_res_path
    
    if(protected_res_path is None):
        protected_res_path = default_protected_res_path
        
    insert_resource(default_protected_res_path, default_passwd)
    
    try:
        # Run the C program with the provided parameters
        result = subprocess.run([executable] + [res_path], capture_output=True, text=True)
        
        # Print the output of the C program
        print("C Program Output:")
        print(result.stdout)
        
        # Print any error output (if any)
        if result.stderr:
            print("C Program Error Output:")
            print(result.stderr)
        
    except FileNotFoundError:
        print(f"Error: The executable '{executable}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
        
    remove_resource(default_protected_res_path, default_passwd)
        
def test_rename(res_path, new_res_path, protected_res_path):
    # Ensure the C executable is in the same directory or provide the full path
    executable = './test_rename'
    
    default_res_path = "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova.txt"
    default_new_res_path = "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/test_rename.txt"
    default_protected_res_path = "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova.txt"
    
    if(res_path is None):
        res_path = default_res_path
        
    if(new_res_path is None):
        new_res_path = default_new_res_path
    
    if(protected_res_path is None):
        protected_res_path = default_protected_res_path
        
    insert_resource(default_protected_res_path, default_passwd)
    
    try:
        # Run the C program with the provided parameters
        result = subprocess.run([executable] + [res_path, new_res_path], capture_output=True, text=True)
        
        # Print the output of the C program
        print("C Program Output:")
        print(result.stdout)
        
        # Print any error output (if any)
        if result.stderr:
            print("C Program Error Output:")
            print(result.stderr)
        
    except FileNotFoundError:
        print(f"Error: The executable '{executable}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
        
    remove_resource(default_protected_res_path, default_passwd)

def test_mkdir(dir_path, protected_dir_path):
    # Ensure the C executable is in the same directory or provide the full path
    executable = './test_mkdir'
    
    default_dir_path = "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova_dir/test_mkdir"
    default_protected_dir_path = "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova_dir"
    
    if(dir_path is None):
        dir_path = default_dir_path
        
    if(protected_dir_path is None):
        protected_dir_path = default_protected_dir_path
        
    insert_resource(default_protected_dir_path, default_passwd)
    
    try:
        # Run the C program with the provided parameters
        result = subprocess.run([executable] + [dir_path], capture_output=True, text=True)
        
        # Print the output of the C program
        print("C Program Output:")
        print(result.stdout)
        
        # Print any error output (if any)
        if result.stderr:
            print("C Program Error Output:")
            print(result.stderr)
        
    except FileNotFoundError:
        print(f"Error: The executable '{executable}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
        
    remove_resource(default_protected_dir_path, default_passwd)

def test_rmdir(dir_path, protected_dir_path):
    # Ensure the C executable is in the same directory or provide the full path
    executable = './test_mkdir'
    
    default_dir_path = "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova_dir/test_rmdir"
    default_protected_dir_path = "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova_dir"
    
    if(dir_path is None):
        dir_path = default_dir_path
        
    if(protected_dir_path is None):
        protected_dir_path = default_protected_dir_path
        
    insert_resource(default_protected_dir_path, default_passwd)
    
    try:
        # Run the C program with the provided parameters
        result = subprocess.run([executable] + [dir_path], capture_output=True, text=True)
        
        # Print the output of the C program
        print("C Program Output:")
        print(result.stdout)
        
        # Print any error output (if any)
        if result.stderr:
            print("C Program Error Output:")
            print(result.stderr)
        
    except FileNotFoundError:
        print(f"Error: The executable '{executable}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
        
    remove_resource(default_protected_dir_path, default_passwd)

def test_mknod(dir_path, protected_dir_path):
    # Ensure the C executable is in the same directory or provide the full path
    executable = './test_mkdir'
    
    default_dir_path = "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova_dir/test_mknod.txt"
    default_protected_dir_path = "/home/matteo/Desktop/kernel-level-reference-monitor/test/files/prova_dir"
    
    if(dir_path is None):
        dir_path = default_dir_path
        
    if(protected_dir_path is None):
        protected_dir_path = default_protected_dir_path
        
    insert_resource(default_protected_dir_path, default_passwd)
    
    try:
        # Run the C program with the provided parameters
        result = subprocess.run([executable] + [dir_path], capture_output=True, text=True)
        
        # Print the output of the C program
        print("C Program Output:")
        print(result.stdout)
        
        # Print any error output (if any)
        if result.stderr:
            print("C Program Error Output:")
            print(result.stderr)
        
    except FileNotFoundError:
        print(f"Error: The executable '{executable}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
        
    remove_resource(default_protected_dir_path, default_passwd)


if __name__ == "__main__":
    
    #Test state transition with correct password
    print("##############TESTING STATE TRANSITION WITH CORRECT PASSWORD##############")
    test_state_transistion(default_passwd)
    
    #Test state transition with incorrect password
    print("##############TESTING STATE TRANSITION WITH INCORRECT PASSWORD##############")
    test_state_transistion("wrong_password")
    
    #return to state REC_ON
    print("##############RETURNING TO REC_ON STATE##############")
    switch_state('2', default_passwd)
    
    #Test insert and remove with correct password
    print("##############TESTING INSERT AND REMOVE WITH CORRECT PASSWORD##############")
    test_insert_remove(None, default_passwd)
    
    #Test insert and remove with incorrect password
    print("##############TESTING INSERT AND REMOVE WITH INCORRECT PASSWORD##############")
    test_insert_remove(None, "wrong_password")
    
    #Test open
    print("##############TESTING OPEN##############")
    test_open(None, None)
    
    '''#Test create
    print("##############TESTING CREATE##############")
    test_create(None, None)
    
    #Test mk_hardlink
    print("##############TESTING MK_HARDLINK##############")
    test_mk_hardlink(None, None, None)
    
    #Test mk_symlink
    print("##############TESTING MK_SYMLINK##############")
    test_mk_symlink(None, None, None)
    
    #Test unlink
    print("##############TESTING UNLINK############")
    test_unlink(None, None)
    
    #Test truncate
    print("##############TESTING TRUNCATE############")
    test_truncate(None, None)
    
    #Test rename
    print("##############TESTING RENAME############")
    test_rename(None, None, None)
    
    #Test mkdir
    print("##############TESTING MKDIR############")
    test_mkdir(None, None)
    
    #Test rmdir
    print("##############TESTING RMDIR############")
    test_rmdir(None, None)
    
    #Test mknod
    print("##############TESTING MKNOD############")
    test_mknod(None, None)'''
    
    
    
    
    
    
    
    

