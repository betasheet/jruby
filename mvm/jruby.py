#! /usr/bin/env python
"""This script is similar to Maxine's "max" script. It enables us to quickly execute
the JRuby interpreter on top of Maxine or the system default JVM.
"""
import os, sys, time
import fnmatch
from optparse import OptionParser
from pprint import pprint
from itertools import product
from measure import measure             ## is from the computer language shootout game...
from tempfile import mkstemp
from collections import defaultdict
import shlex
import datetime
import pickle
from math import *
import shutil
import csv
import numpy
import glob
import benchmark

def get_env():
    """This function returns a dictionary that contains the actual values for environment
    variables. This is platform specific (since we are relying on the platform identifier
    in Maxine's build directory. Currently, Linux [verified on Ubuntu 10.04+] and MacOS X
    are supported.
    NOTE: This function is not supposed to be called directly, rather use one of the pre-
    defined access functions that bind the environment and the key as a default argument,
    e.g.: get_maxine_executable().
    """
    currentDir = os.path.abspath('.')
    ## maxineProjects = ()
    maxineDir = os.path.abspath('../..')

    platform= sys.platform ## returns 'darwin' on macosx, 'linux2' on ubuntu 10.04
    if platform == 'linux2':
        platform= 'linux'

    maxineExe = maxineDir + "/com.oracle.max.vm.native/generated/%s/maxvm " % platform
    maxineInspector = maxineDir + "/mxtool/mx inspect"

    jrubyProjectPath = ".."
    jrubyScriptsPath = currentDir + "/testscripts"

    classpath = []

    # JRuby stuff
    jrubyDir = os.path.join(maxineDir, 'jruby')
    jrubyDist = os.path.join(jrubyDir, 'lib')
#    jrubyDistJavaLib = os.path.join(jrubyDist, 'javalib')

#     if os.path.exists(jrubyDistJavaLib):
#         os.chdir(jrubyDistJavaLib)
#         classpath = [os.path.join(jrubyDistJavaLib, cp) for cp in glob.glob('*.jar')]
#         os.chdir(jrubyDist)
#         jrubyJarFile = os.path.join(jrubyDist, glob.glob('jruby-dev.jar')[0])
#         classpath.append(jrubyJarFile)
#         classpath = tuple(classpath)
#         os.chdir(currentDir)

    jrubyJarFile = os.path.join(jrubyDist, 'jruby.jar')

    classpath.append(jrubyJarFile)
    classpath = tuple(classpath)

    return {
        'executable' : maxineExe,
        'maxinspect' : maxineInspector,
        'prj'        : jrubyProjectPath,
        'scripts'    : jrubyScriptsPath,
        'cp'         : classpath,
        'current'    : currentDir,
        'maxine'     : maxineDir
        }


def get_maxine_home(env=get_env(), key='maxine'):
    return env[key]

def get_maxine_executable(env=get_env(), key='executable'):
    return env[key]

def get_maxine_inspector(env=get_env(), key='maxinspect'):
    return env[key]

def get_maxine_prj(env=get_env(), key='prj'):
    return env[key]

def get_maxine_scripts(env=get_env(), key='scripts'):
    return env[key]

def get_maxine_classpath(env=get_env(), key='cp'):
    return ':'.join(env[key])

def get_cwd(env=get_env(), key='current'):
    return env[key]

def check_config():
    """This function verifies that some paths exist in the current configuration. If
    it fails, it reports an error to the caller and exits.
    """
    rules= [
        (get_maxine_prj(), "Invalid project path"),
        (get_maxine_scripts(), "Invalid scripts path"),
        ]
    for (p, errmsg) in rules:
        if not os.path.exists( p ):
            exit( "%s: %s" % (errmsg, p) )


def parse_cmd_line_args():
    """This defines the command line arguments supported by our tool.
    """
    p = OptionParser()

    p.add_option("-o", "--host",    action="store",      dest="host",    default="",    help="options to pass to the Host VM")
    p.add_option("-O", "--client",  action="store",      dest="client",  default="",    help="options to pass to the Client VM")
    p.add_option("-x", "--execute", action="store",      dest="execute", default="",    help="executes a specified script: {" + ", ".join(os.listdir(get_maxine_scripts())) + "}")
    p.add_option("-r", "--run",     action="store_true", dest="run",     default=False, help="run all scripts")
    p.add_option("-m", "--max",     action="store_true", dest="max",     default=False, help="run on top of maxine")
    p.add_option("-i", "--ins",     action="store_true", dest="ins",     default=False, help="run on top of maxine inspector")
    p.add_option("-z", "--bench",   action="store",      dest="bench",   type='int',    default=0, help="run benchmarks and print results")
    p.add_option("-p", "--perf",    action="store",      dest="perf",    default="",    help="options to pass to perf tool (linux only)")

    return p.parse_args()

def get_exec(cmd_class="org.jruby.Main", action_args=[]):
    """This function returns a closure that holds partially bound arguments for executing
    programs using the "os.system" invocation function. The closure is used so that we can
    late bind arguments depending on the passed command line options. Furthermore, the when
    we execute the closure it will keep track of the exit codes and populate the corresponding
    "errors" list.
    """
    def exec_closure(args=[], host_vm_opts='', client_vm_opts='', use_maxine=False, use_inspector=False, errors=[]):
        executable= 'java'

        if use_inspector:
            executable = get_maxine_inspector()
            host_vm_opts = ''
            os.chdir(get_maxine_home())
        elif use_maxine:
            executable = get_maxine_executable()
            #host_vm_opts += ' -C1X:+ExceptionHandlingElimination -C1X:EHEFilter=Lorg/python/core/PyThreadedCodeInterpreter,Lorg/python/core/PyBytecode,Lorg/python/core/PyBaseCode'

        arguments= ' '.join(action_args + args)

        if opts.perf:
            executable = "perf %s %s" % (opts.perf, executable)


        command= "%s %s -cp %s %s %s %s" % (executable,
                                         host_vm_opts,
                                         get_maxine_classpath(),
                                         cmd_class,
                                         client_vm_opts,
                                         arguments)
        #print "Executing:", command
        start= time.time()
        exit_code= os.system( command )
        elapsed= time.time() - start
        if exit_code:
            errors.append( (executable, host_vm_opts, client_vm_opts, cmd_class, arguments) )

    return exec_closure

def enum_scripts(filter_fn=lambda x: True, script_path=get_maxine_scripts()):
    """This function is used to enumerate the scripts found in the script path. At the
    same time you can supply a custom "filter_fn" function to filter out unwanted entries
    from the input directory.
    NOTE: If this function finds a file called ".mbsignore" in the directory specified by
    the named "script_path" argument, it will exclude all files listed in there.
    """
    files_to_run= "%s/.run" % (script_path)

    if not os.path.exists(files_to_run):
        exit(files_to_run +  " does not exist")

    with open(files_to_run) as input:
        for s in input:
            if filter_fn(s):
                #script = os.path.join(script_path, s.strip())
                yield s.strip()

def run_gn(script_path=os.path.abspath(get_maxine_scripts())):
    for s in enum_scripts(filter_fn= lambda x: not x.startswith('#') ):
        print "Running ... %s" % (s)

        yield get_exec(action_args=[os.path.join(script_path, s)])

def expand_file_information(tuples):
    """This function takes in a list of tuples as generated by "run_bmarks_gn" and
    expands the information stored within the temporary files generated by "run_bmarks_gn".
    The protocol is that the last line contains the running time of the benchmark as calculated
    in the benchmark (this is rather fuzzy though, as it is still in the interpreter and should
    actually be measured on the virtual machine level; probably a more accurate measurement
    technique would be to measure whole process execution as stored in the measure record "r" and
    subtract the VM start-up time.). All other information present in the file can be used for
    verification purposes, i.e., the results can later be compared to the outputs of other
    interpreters.
    (NOTE: printing to stdout is going to make most of the benchmark measurements useless)

    Finally, we generate a new list of tuples, with the information conveniently expanded
    for use by other functions.
    """
    results= []
    for (native, host, s, path, r) in tuples:
        with open(path) as f:
            lines= f.readlines()
            try:
                # if last line is time, the second last line is also ignored for the timer label
                prog_output, prog_runtime= lines[:-2], float(lines[-1])
                results.append( (native, host, s, prog_runtime, prog_output, path, r) )
            except:
                # bypass time extraction and carry on
                # if last line is not time, all lines are taken
                prog_output, prog_runtime= lines, float(0)
                results.append( (native, host, s, prog_runtime, prog_output, path, r) )

    return results

def escape_r(v):
    if v == None:
        return "NA"
    try:
        return str(float(v))
    except:
        return "\"" + str(v) + "\""

def run_bmarks_gn(script_path=os.path.abspath(get_maxine_scripts())):
    native_vm_runtimes= [
#          ("hotspot", "java")
#          , ("hotspot", "java")
          #("maxine", get_maxine_executable() + '-XX:+TimeCompilation')
          ("maxine", get_maxine_executable())
          , ("maxine", get_maxine_executable())
          #("maxine", get_maxine_executable() + '-XX:+TimeCompilation -C1X:+ExceptionHandlingElimination -C1X:EHEFilter=Lorg/python/core/PyThreadedCodeInterpreter,Lorg/python/core/PyBytecode')
          #, ("maxine", get_maxine_executable() + '-C1X:+ExceptionHandlingElimination -C1X:EHEFilter=Lorg/python/core/PyThreadedCodeInterpreter,Lorg/python/core/PyBytecode')
        ]

    host_vms= [
          #("ast", "org.jruby.Main -trun -X-C", "")
           ("jit", "org.jruby.Main -trun", "")
          , ("yarv", "org.jruby.Main -tinterpret -X-y", "bytecode")
          #, ("yarv-si", "org.jruby.Main -tinterpret -X-ysi", "bytecode")
        ]

    results= []
    try:
        index= 0
        with open('/dev/null', 'w') as throwaway:
            for (native, host) in zip(native_vm_runtimes, host_vms):
                print "Benchmarking %s on %s" % (host, native)
                for s in enum_scripts(filter_fn= lambda x: not x.startswith('#') ):
                    job = s
                    if host[2] == "bytecode":
                        script_list = s.split(' ')
                        script_list[0] = script_list[0] + '.bin'
                        job = ' '.join(script_list)
                        job = os.path.join(os.path.join(script_path, 'binarycode'), job)
                    else:
                        job = os.path.join(script_path, job)
                    print "\trunning %35s" % (job.split('/')[-1]),


                    cmd_line= "%s -cp %s %s %s" % (native[1],
                                                   get_maxine_classpath(),
                                                   host[1],
                                                   job)
                    cmd= shlex.split(cmd_line)

                    print " -- ",
                    for iteration in range(0, opts.bench):
                        print "%d," % iteration,
                        sys.stdout.flush()
                        retry= True
                        while retry:
                            (output, path)= mkstemp(prefix="mbs") ##prefix="%s-%s-%s" % (native, host, s))
                            result= measure(index, cmd, 0, 1000000, outFile=throwaway, errFile=output)
                            os.close(output)
                            if result.isOkay():
                                results.append( (native, host, s, path, result) )
                                index+= 1
                                retry= False
                            else:
                                print "(faulted; retrying)",

                    print
        print "Gathering data complete..."
        results= expand_file_information(results)

        print "Saving results to file ..."
        with open("res.out", 'w') as output:
            output.write(pickle.dumps(results))
    except:
        if os.path.exists("res.out"):
            print "Loading results from file ..."
            with open("res.out", 'r') as input:
                results= pickle.loads(input.read())

    benchmark.process(results, host_vms)
    return []

def execute_script(script_filename, script_path=os.path.abspath(get_maxine_scripts())):
    """This function returns another closure so that we can bind the name of the script
    to be executed ("script_filename") to the execution closure. This is necessary because
    this filename comes from the OptionParser and needs to be made available to the
    execution closure in one way or another.
    """
    def closure():
        path= "%s/%s" % (script_path, script_filename)
        if not os.path.exists(path):
            exit('Specified script does not exist: %s' % path)

        yield get_exec(action_args=[path])
    return closure

def show_errors(errors, total_execs):
    print "#" * 80
    print "Summary:"
    print "\t%d out of %d execs failed:" % (len(errors), total_execs)
    for (executable, host_vm_opts, client_vm_opts, cmd_class, arguments) in errors:
        print "\t\t%s" % (arguments)

if __name__ == "__main__":
    check_config()
    (opts, args)= parse_cmd_line_args()

    driver= {
        ## binds a command line argument to an action...
        'execute' : execute_script(opts.execute),
        'run'     : run_gn,
        'bench'   : run_bmarks_gn,
        }

    ## the protocol is fairly easy and enables flexible arrangement of various actions
    ## and keeping passing of options and arguments hassle-free, too.
    ## the procedure is:
    ## 1) iterate over the driver-table and find which actions are specified,
    ## 2) execute the function specified in the table, these functions *MUST*
    ##    return an iterable data structure of callables (i.e., either a list or
    ##    a generator of functions),
    ## 3) call all functions of the list of step (2), supplying the action-independent
    ##    options and arguments.
    errors= []
    total_execs= 0
    for (key, iter_fn) in driver.iteritems():
        if hasattr(opts, key) and getattr(opts, key):
            for f in iter_fn():
                f(args=args, host_vm_opts=opts.host, client_vm_opts=opts.client,
                    use_maxine=opts.max, use_inspector=opts.ins, errors=errors)
                total_execs+= 1

    if errors:
        show_errors(errors, total_execs)


