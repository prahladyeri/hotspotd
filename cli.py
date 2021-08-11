# -*- coding: utf-8 -*-

# @author: Prahlad Yeri
# @description: Common functions to interface with linux cli
# @license: MIT

import os
import subprocess
# ,SimpleHTTPServer,SocketServer

arguments = None


def get_stdout(pi):
    """Return the stdout."""
    result = pi.communicate()
    if len(result[0]):
        return result[0]
    else:
        return result[1]  # some error has occurred


def kill_all(process):
    """Kill process."""
    cnt = 0
    pid = is_process_running(process)
    while pid != 0:
        execute_shell('kill ' + str(pid))
        pid = is_process_running(process)
        cnt += 1
    return cnt


def execute_shell(command, error=''):
    """Execute a shell command."""
    return execute(command, wait=True, shellexec=True, errorstring=error)


def execute(command='', errorstring='', wait=True, shellexec=False, ags=None):
    """Execute a shell command."""
    try:
        if shellexec:
            p = subprocess.Popen(command, shell=True,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            # print 'verb: ' + str(arguments.verbose)
            if arguments.verbose:
                print 'command: ' + command
        else:
            p = subprocess.Popen(args=ags)
            if arguments.verbose:
                print 'command: ' + ags[0]

        if wait:
            p.wait()
            result = get_stdout(p)
            return result
        else:
            if arguments.verbose:
                print 'not waiting'
            return p
    except subprocess.CalledProcessError:
        print 'error occurred:' + errorstring
        return errorstring
    except Exception as ea:
        print 'Exception occurred:' + ea.message
        return errorstring
        # show_message("Error occurred: " + ea.message)


def is_process_running(name):
    """Return the process running state."""
    cmd = 'ps aux |grep ' + name + ' |grep -v grep'
    s = execute_shell(cmd)
    # return len(s)>0
    if len(s):
        return 0
    else:
        t = s.split()
        return int(t[1])


def check_sysfile(filename):
    """Check file existence."""
    if os.path.exists('/usr/sbin/' + filename):
        return '/usr/sbin/' + filename
    elif os.path.exists('/sbin/' + filename):
        return '/sbin/' + filename
    else:
        return ''


def get_sysctl(setting):
    """Return sysctl result."""
    result = execute_shell('sysctl ' + setting)
    if '=' in result:
        return result.split('=')[1].lstrip()
    else:
        return result


def set_sysctl(setting, value):
    """Set??"""
    # Setters don't return anything
    return execute_shell('sysctl -w ' + setting + '=' + value)


def write_log(message):
    if arguments.verbose:
        print message
    # ~ global tbuffer
    # ~ #tbuffer.insert_at_cursor(message + '\n')
    # ~ tbuffer.insert(tbuffer.get_end_iter(),message.strip() + '\n')
    # ~ while Gtk.events_pending():
    #     ~ Gtk.main_iteration()
    # ~ #tbuffer.set_text(message + '\n')
