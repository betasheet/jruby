package org.jruby.ast.executable;

import java.util.ArrayList;
import java.util.List;

import org.jruby.MetaClass;
import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyBignum;
import org.jruby.RubyClass;
import org.jruby.RubyFixnum;
import org.jruby.RubyHash;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.RubyRange;
import org.jruby.RubyRegexp;
import org.jruby.RubyString;
import org.jruby.ast.executable.YARVMachine.InstructionSequence.InlineCache;
import org.jruby.javasupport.util.RuntimeHelpers;
import org.jruby.parser.StaticScope;
import org.jruby.runtime.Arity;
import org.jruby.runtime.Binding;
import org.jruby.runtime.Block;
import org.jruby.runtime.BlockBody;
import org.jruby.runtime.CallSite;
import org.jruby.runtime.DynamicScope;
import org.jruby.runtime.MethodIndex;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.RubyEvent;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.YARVBlockBody;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.runtime.scope.ManyVarsDynamicScope;
import org.jruby.util.ByteList;
import org.jruby.util.RegexpOptions;

public class YARVMachine {

    private static final boolean TAILCALL_OPT = Boolean.getBoolean("jruby.tailcall.enabled");

    public static List<YARVMachine> INSTANCES = new ArrayList<YARVMachine>(32);

    public static YARVMachine getInstance() {
        int tid = (int) Thread.currentThread().getId();

        while (INSTANCES.size() <= tid) {
            INSTANCES.add(null);
        }

        YARVMachine machine = INSTANCES.get(tid);
        if (machine == null) {
            INSTANCES.set(tid, machine = new YARVMachine());
        }

        return machine;
    }

    public static int instruction(String name) {
        return YARVInstructions.instruction(name);
    }

    public static class InstructionSequence extends RubyObject {

        public class InlineCache {
            public long state;
            public IRubyObject cachedObject;
        }
        
        public String magic;
        public int major;
        public int minor;
        public int format_type;
        public Object misc;
        public String name;
        public String filename;
        public String filefullpath;
        public int line;
        public String type;

        public String[] locals;
        public int local_size;

        public int args_argc;
        public String[] args_opt_labels;
        public int args_post_len;
        public int args_post_start;
        public int args_rest;
        public int args_block;
        public int args_simple;

        public Object[] exception;

        public Instruction[] body;

        public InstructionSequence(Ruby runtime, RubyClass metaClass, String name, String file,
                String type) {
            super(runtime, metaClass);

            magic = "YARVInstructionSimpledataFormat";
            major = 1;
            minor = 1;
            format_type = 1;
            misc = runtime.getNil();
            this.name = name;
            this.filename = file;
            this.line = 0;
            this.type = type;
            this.locals = new String[0];
            this.args_argc = 0;
            this.exception = new Object[0];
        }

        public static RubyClass createInstructionSequence(Ruby runtime) {
            RubyClass iseq = runtime.defineClass("InstructionSequence", runtime.getClass("Data"),
                    ObjectAllocator.NOT_ALLOCATABLE_ALLOCATOR);

            iseq.defineAnnotatedMethods(InstructionSequence.class);

            return iseq;
        }

        /**
         * @return
         */
        public int getOptArgsLength() {
            return args_opt_labels == null ? 0 : args_opt_labels.length;
        }
        
        private InlineCache[] inlineCaches = new InlineCache[1024];

        private InlineCache getInlineCache(int id) {
            if (inlineCaches[id] == null)
                inlineCaches[id] = new InlineCache();
            return inlineCaches[id];
        }
    }

    public static class Instruction {
        public int bytecode;
        public int line_no;
        public String s_op0;
        public IRubyObject o_op0;
        public Object _tmp;
        public long l_op0;
        public long l_op1;
        public int i_op1;
        public InstructionSequence iseq_op;
        public Instruction[] ins_op;
        public int i_op3;
        public int i_op2;

        public int index;
        public int methodIndex = -1;
        public CallSite callAdapter;

        public Instruction(int bytecode) {
            this.bytecode = bytecode;
        }

        public Instruction(int bytecode, String op) {
            this.bytecode = bytecode;
            this.s_op0 = op.intern();
        }

        public Instruction(int bytecode, String op, InstructionSequence op1) {
            this.bytecode = bytecode;
            this.s_op0 = op.intern();
            this.iseq_op = op1;
        }

        public Instruction(int bytecode, long op) {
            this.bytecode = bytecode;
            this.l_op0 = op;
        }

        public Instruction(int bytecode, IRubyObject op) {
            this.bytecode = bytecode;
            this.o_op0 = op;
        }

        public Instruction(int bytecode, String op, int op1, Instruction[] op2, int op3) {
            this.bytecode = bytecode;
            this.s_op0 = op;
            this.i_op1 = op1;
            this.ins_op = op2;
            this.i_op3 = op3;
        }

        @Override
        public String toString() {
            return "[:" + YARVInstructions.name(bytecode) + ", "
                    + (s_op0 != null ? s_op0 : (o_op0 != null ? o_op0.toString() : ("" + l_op0)))
                    + "]";
        }
    }

    IRubyObject[] stack = new IRubyObject[8192];
    public int stackTop = 0;

    /*
     * private void printStack(String message, int fromIndex) {
     * System.out.println("(" + message + ") Stack:"); for (int i = fromIndex; i
     * < stackTop; i++) { System.out.println("" + i + ": " + (stack[i] == null ?
     * "null" : stack[i].inspect().toString())); } }
     */

    /**
     * Push a value onto the stack
     * 
     * @param value
     *            to be pushed
     */
    private void push(IRubyObject value) {
        // System.out.println("push(" + value.inspect() + ")");
        stack[stackTop] = value;
        stackTop++;
    }

    /**
     * Swap top two values in the stack
     */
    private void swap() {
        stack[stackTop] = stack[stackTop - 1];
        stack[stackTop - 1] = stack[stackTop - 2];
        stack[stackTop - 2] = stack[stackTop];
    }

    /**
     * Duplicate top 'n' values in the stack
     * 
     * @param length
     */
    private void dupn(int length) {
        System.arraycopy(stack, stackTop - length, stack, stackTop, length);
        stackTop += length;
    }

    /**
     * Peek at top value in the stack
     * 
     * @return the top value
     */
    private IRubyObject peek() {
        return stack[stackTop - 1];
    }

    /**
     * pop top value in the stack
     * 
     * @return the top value
     */
    private IRubyObject pop() {
        // System.out.println("pop(" + stack[stackTop-1].inspect() + ")");
        return stack[--stackTop];
    }

    /**
     * Pop top arr.length values into supplied arr.
     * 
     * @param arr
     *            to be populated from the stack
     * @return the array passed in
     */
    private IRubyObject[] popArray(IRubyObject arr[]) {
        stackTop -= arr.length;
        System.arraycopy(stack, stackTop, arr, 0, arr.length);

        /*
         * System.out.print("popArray:"); for (int i = 0; i < arr.length; i++) {
         * System.out.print(" " + arr[0].inspect()); } System.out.println("");
         */

        return arr;
    }

    /**
     * Push top arr.length values from supplied arr onto stack.
     * 
     * @param arr
     *            contains elements to be pushed to the stack
     */
    private void pushArray(RubyArray arr) {
        System.arraycopy(arr.toJavaArrayUnsafe(), 0, stack, stackTop, arr.getLength());
        stackTop += arr.getLength();
    }

    /**
     * set the nth stack value to value
     * 
     * @param depth
     *            nth index of stack
     * @param value
     *            to be set
     */
    private void setn(int depth, IRubyObject value) {
        stack[stackTop - depth - 1] = value;
    }

    /**
     * push nth stack value
     * 
     * @param depth
     *            which element to push
     */
    private void topn(int depth) {
        push(stack[stackTop - depth - 1]);
    }

    /**
     * Set/Replace top stack value with value
     * 
     * @param value
     *            to replace current stack value
     */
    public void set(IRubyObject value) {
        stack[stackTop - 1] = value;
    }

    public void unimplemented(int bytecode) {
        System.err.println("Not implemented, YARVMachine." + YARVInstructions.name(bytecode));
    }

    /**
     * Top-level exec into YARV machine.
     * 
     * @param context
     *            thread that is executing this machine (Note: We need to make n
     *            machines with each belonging to an individual context)
     * @param scope
     *            of exec (evals will sometimes pass in something interesting)
     * @param bytecodes
     *            to be executed
     * @return last value pop'd of machine stack
     */
    public IRubyObject exec(ThreadContext context, StaticScope scope, InstructionSequence iseq) {
        try {
            IRubyObject self = context.getRuntime().getObject();

            context.preScopedBody(new ManyVarsDynamicScope(scope));

            if (scope.getModule() == null) {
                scope.setModule(context.getRuntime().getObject());
            }

            return exec(context, self, iseq);
        } finally {
            context.postScopedBody();
        }
    }

    public IRubyObject exec(ThreadContext context, IRubyObject self, InstructionSequence iseq) {
        Ruby runtime = context.getRuntime();

        RubyClass vmCore = YARVVMCore.createYARVVMCore(runtime);
        Instruction[] bytecodes = iseq.body;

        // Where this frames stack begins.
        int stackStart = stackTop;
        int ip = 0;
        IRubyObject other;

        yarvloop: while (ip < bytecodes.length) {
// System.err.println("Executing: " + bytecodes[ip].toString() + " (ip=" + ip +
// ")");
            switch (bytecodes[ip].bytecode) {
            case YARVInstructions.NOP:
                break;
            case YARVInstructions.GETGLOBAL:
                push(runtime.getGlobalVariables().get(bytecodes[ip].s_op0));
                break;
            case YARVInstructions.SETGLOBAL:
                runtime.getGlobalVariables().set(bytecodes[ip].s_op0, pop());
                break;
            case YARVInstructions.GETLOCAL: {
                DynamicScope scope = context.getCurrentScope().localScope;
                int idx = scope.getStaticScope().getNumberOfVariables() - (int) bytecodes[ip].l_op0;
                push(scope.getValue(idx, 0));
                break;
            }
            case YARVInstructions.SETLOCAL: {
                DynamicScope scope = context.getCurrentScope().localScope;
                int idx = scope.getStaticScope().getNumberOfVariables() - (int) bytecodes[ip].l_op0;
                scope.setValue(idx, pop(), 0);
                break;
            }
            case YARVInstructions.GETDYNAMIC: {
                int depth = (int) bytecodes[ip].l_op1;
                DynamicScope scope = context.getCurrentScope();
                if (depth > 0) {
                    scope = scope.getNthParentScope(depth);
                }
                int idx = scope.getStaticScope().getNumberOfVariables() - (int) bytecodes[ip].l_op0;
                push(scope.getValue(idx, 0));
                break;
            }
            case YARVInstructions.SETDYNAMIC: {
                int depth = (int) bytecodes[ip].l_op1;
                DynamicScope scope = context.getCurrentScope();
                if (depth > 0) {
                    scope = scope.getNthParentScope(depth);
                }
                int idx = scope.getStaticScope().getNumberOfVariables() - (int) bytecodes[ip].l_op0;
                scope.setValue(idx, pop(), 0);
                break;
            }
            case YARVInstructions.GETINSTANCEVARIABLE:
                push(self.getInstanceVariables().getInstanceVariable(bytecodes[ip].s_op0));
                break;
            case YARVInstructions.SETINSTANCEVARIABLE:
                self.getInstanceVariables().setInstanceVariable(bytecodes[ip].s_op0, pop());
                break;
            case YARVInstructions.GETCLASSVARIABLE: {
                RubyModule rubyClass = context.getRubyClass();
                String name = bytecodes[ip].s_op0;

                if (rubyClass == null) {
                    push(self.getMetaClass().getClassVar(name));
                } else if (!rubyClass.isSingleton()) {
                    push(rubyClass.getClassVar(name));
                } else {
                    RubyModule module = (RubyModule) (((MetaClass) rubyClass).getAttached());

                    if (module != null) {
                        push(module.getClassVar(name));
                    } else {
                        push(runtime.getNil());
                    }
                }
                break;
            }
            case YARVInstructions.SETCLASSVARIABLE: {
                RubyModule rubyClass = context.getCurrentScope().getStaticScope().getModule();

                if (rubyClass == null) {
                    rubyClass = self.getMetaClass();
                } else if (rubyClass.isSingleton()) {
                    rubyClass = (RubyModule) (((MetaClass) rubyClass).getAttached());
                }

                rubyClass.setClassVar(bytecodes[ip].s_op0, pop());
                break;
            }
            case YARVInstructions.GETCONSTANT: {
                IRubyObject klass = pop();
                if (klass == null || klass == runtime.getNil()) {
                    push(context.getCurrentStaticScope().getConstant(bytecodes[ip].s_op0));
                } else {
                    push(((RubyModule) klass).getConstant(bytecodes[ip].s_op0));
                }
                break;
            }
            case YARVInstructions.SETCONSTANT: {
                IRubyObject klass = pop();
                if (klass == null || klass == runtime.getNil()) {
                    IRubyObject value = pop();
                    context.getCurrentStaticScope().setConstant(bytecodes[ip].s_op0, value);
                    runtime.incGlobalState();
                } else {
                    IRubyObject value = pop();
                    push(((RubyModule) klass).setConstant(bytecodes[ip].s_op0, value));
                    runtime.incGlobalState();
                }
                break;
            }
            case YARVInstructions.PUTNIL:
                push(context.getRuntime().getNil());
                break;
            case YARVInstructions.PUTSELF:
                push(self);
                break;
            case YARVInstructions.PUTOBJECT:
                // System.out.println("PUTOBJECT: " + bytecodes[ip].o_op0);
                push(bytecodes[ip].o_op0);
                break;
            case YARVInstructions.PUTSPECIALOBJECT:
                // TODO cbase / const base difference (put by eval?
// vm_insnhelper.c)
                if (bytecodes[ip].l_op0 == 1) { // VM_SPECIAL_OBJECT_VMCORE
                    push(vmCore);
                } else if (bytecodes[ip].l_op0 == 2) { // VM_SPECIAL_OBJECT_CBASE
                    push(context.getRubyClass());
                } else if (bytecodes[ip].l_op0 == 3) { // VM_SPECIAL_OBJECT_CONST_BASE
                    push(context.getRubyClass());
                } else {
                    unimplemented(YARVInstructions.PUTSPECIALOBJECT);
                }
                break;
            case YARVInstructions.PUTISEQ:
                push(bytecodes[ip].iseq_op);
                break;
            case YARVInstructions.DEFINECLASS: {
                IRubyObject parentClass = pop();
                IRubyObject cBase = pop();
                String name = bytecodes[ip].s_op0;
                boolean isRedefine = (parentClass == runtime.getFalse());
                InstructionSequence cIseq = bytecodes[ip].iseq_op;

                switch (bytecodes[ip].i_op2) {
                case 0: /* scoped: class Foo::Bar */
                case 3: /* no scope: class Bar */
                    if (parentClass == runtime.getNil()) {
                        parentClass = runtime.getObject();
                    }

                    if (cBase == runtime.getNil() || cBase == null) {
                        cBase = runtime.getObject();
                    }

                    RubyClass newClass = ((RubyClass) cBase).getClass(name);
                    if (newClass == null || isRedefine) {
                        if (isRedefine) {
                            parentClass = newClass.getSuperClass();
                        }
                        newClass = ((RubyClass) cBase).defineClassUnder(name,
                                (RubyClass) parentClass, ((RubyClass) parentClass).getAllocator());
                    }

                    StaticScope sco = runtime.getStaticScopeFactory().newLocalScope(
                            context.getCurrentStaticScope());
                    sco.setVariables(cIseq.locals);
                    sco.setModule(newClass);

                    context.preClassEval(sco, newClass);

                    try {
                        if (runtime.hasEventHooks()) {
                            callTraceFunction(runtime, context, RubyEvent.CLASS);
                        }

                        YARVMachine.getInstance().exec(context, newClass, cIseq);
                    } finally {
                        try {
                            if (runtime.hasEventHooks()) {
                                callTraceFunction(runtime, context, RubyEvent.END);
                            }
                        } finally {
                            context.postClassEval();
                        }
                    }

                    break;
                case 1:
                    unimplemented(YARVInstructions.DEFINECLASS);
                    break;
                case 2: /* scoped: module Foo::Bar or module ::Bar */
                case 5: /* no scope: module Bar */
                    unimplemented(YARVInstructions.DEFINECLASS);
                    break;
                default:
                    unimplemented(YARVInstructions.DEFINECLASS);
                }

                push(runtime.getNil());
                break;
            }
            case YARVInstructions.PUTSTRING:
                push(context.getRuntime().newString(bytecodes[ip].s_op0));
                break;
            case YARVInstructions.CONCATSTRINGS: {
                StringBuilder concatter = new StringBuilder();

                for (int i = (int) (stackTop - bytecodes[ip].l_op0); i < stackTop; i++) {
                    concatter.append(stack[i].toString());
                }
                stackTop -= bytecodes[ip].l_op0;

                push(runtime.newString(concatter.toString()));
                break;
            }
            case YARVInstructions.TOSTRING:
                IRubyObject top = peek();
                if (!(top instanceof RubyString)) {
                    set(top.callMethod(context, "to_s"));
                }
                break;
            case YARVInstructions.TOREGEXP: {
                int count = (int) bytecodes[ip].l_op1;
                byte[][] parts = new byte[count][];
                int size = 0;
                for (int i = count - 1; i >= 0; i--) {
                    IRubyObject part = pop();
                    if (part instanceof RubyString) {
                        String str = part.asJavaString();
                        parts[i] = str.getBytes();
                        size += parts[i].length;
                    } else {
                        System.err.println("unexpected part in regex creation");
                    }
                }
                ByteList pattern = new ByteList(size);
                for (int i = 0; i < count; i++) {
                    pattern.append(parts[i]);
                }
                push(RubyRegexp.newRegexp(runtime, pattern,
                        RegexpOptions.fromJoniOptions((int) bytecodes[ip].l_op0)));
                break;
            }
            case YARVInstructions.NEWARRAY:
                push(runtime.newArrayNoCopy(popArray(new IRubyObject[(int) bytecodes[ip].l_op0])));
                break;
            case YARVInstructions.DUPARRAY:
                push(bytecodes[ip].o_op0.dup());
                break;
            case YARVInstructions.EXPANDARRAY: {
                IRubyObject ary = pop();
                if (ary != null && ary instanceof RubyArray) {
                    RubyArray array = (RubyArray) ary;
// for (int i = 0; i < ((int) bytecodes[ip].l_op0); i++) {
                    for (int i = ((int) bytecodes[ip].l_op0) - 1; i >= 0; i--) {
                        push(array.entry(i));
                    }
                    // TODO support for flag
                } else {
                    push(ary);
                    for (int i = 1; i < ((int) bytecodes[ip].l_op0); i++) {
                        push(runtime.getNil());
                    }
                }
                break;
            }
            case YARVInstructions.NEWHASH:
                int hsize = (int) bytecodes[ip].l_op0;
                RubyHash h = RubyHash.newHash(runtime);
                IRubyObject v,
                k;
                for (int i = hsize; i > 0; i -= 2) {
                    v = pop();
                    k = pop();
                    h.op_aset(context, k, v);
                }
                push(h);
                break;
            case YARVInstructions.NEWRANGE:
                // high, low, flag
                IRubyObject end = pop();
                IRubyObject begin = pop();
                push(RubyRange.newRange(runtime, context, begin, end, bytecodes[ip].l_op0 != 0));
                break;
            case YARVInstructions.POP:
                pop();
                break;
            case YARVInstructions.DUP:
                push(peek());
                break;
            case YARVInstructions.DUPN:
                dupn((int) bytecodes[ip].l_op0);
                break;
            case YARVInstructions.SWAP:
                swap();
                break;
            case YARVInstructions.TOPN:
                topn((int) bytecodes[ip].l_op0);
                break;
            case YARVInstructions.SETN:
                setn((int) bytecodes[ip].l_op0, peek());
                break;
            case YARVInstructions.SEND: {
                ip = send(runtime, context, self, bytecodes, stackStart, ip);
                break;
            }
            case YARVInstructions.LEAVE:
                break yarvloop;
            case YARVInstructions.JUMP:
                ip = (int) bytecodes[ip].l_op0;
                continue yarvloop;
            case YARVInstructions.BRANCHIF:
                ip = pop().isTrue() ? (int) bytecodes[ip].l_op0 : ip + 1;
                continue yarvloop;
            case YARVInstructions.BRANCHUNLESS: {
                ip = !pop().isTrue() ? (int) bytecodes[ip].l_op0 : ip + 1;
                continue yarvloop;
            }
            case YARVInstructions.ONCEINLINECACHE:
            case YARVInstructions.GETINLINECACHE: {
                InlineCache ic = iseq.getInlineCache((int) bytecodes[ip].l_op1);
                if (ic.state == runtime.getGlobalState()) {
                    push(ic.cachedObject);
                    ip = (int) bytecodes[ip].l_op0;
                    continue yarvloop;
                }
                push(runtime.getNil());
                break;
            }
            case YARVInstructions.SETINLINECACHE: {
                InlineCache ic = iseq.getInlineCache((int) bytecodes[ip].l_op0);
                ic.state = runtime.getGlobalState();
                ic.cachedObject = peek();
                break;
            }
            case YARVInstructions.OPT_PLUS:
                op_plus(runtime, context, pop(), pop());
                break;
            case YARVInstructions.OPT_MINUS:
                op_minus(runtime, context, pop(), pop());
                break;
            case YARVInstructions.OPT_MULT:
                other = pop();
                push(pop().callMethod(context, "*", other));
                break;
            case YARVInstructions.OPT_DIV:
                other = pop();
                push(pop().callMethod(context, "/", other));
                break;
            case YARVInstructions.OPT_MOD:
                other = pop();
                push(pop().callMethod(context, "%", other));
                break;
            case YARVInstructions.OPT_EQ:
                other = pop();
                push(pop().callMethod(context, "==", other));
                break;
            case YARVInstructions.OPT_NEQ:
                other = pop();
                push(pop().callMethod(context, "!=", other));
                break;
            case YARVInstructions.OPT_LT:
                op_lt(runtime, context, pop(), pop());
                break;
            case YARVInstructions.OPT_LE:
                other = pop();
                push(pop().callMethod(context, "<=", other));
                break;
            case YARVInstructions.OPT_LTLT:
                other = pop();
                push(pop().callMethod(context, "<<", other));
                break;
            case YARVInstructions.OPT_GT:
                op_gt(runtime, context, pop(), pop());
                break;
            case YARVInstructions.OPT_GE:
                other = pop();
                push(pop().callMethod(context, ">=", other));
                break;
            case YARVInstructions.OPT_AREF:
                other = pop();
                push(pop().callMethod(context, "[]", other));
                break;
            case YARVInstructions.OPT_ASET: {
                // YARV will never emit this, for some reason.
                IRubyObject value = pop();
                other = pop();
                push(RuntimeHelpers.invoke(context, pop(), "[]=", other, value));
                break;
            }
            case YARVInstructions.OPT_LENGTH:
                push(pop().callMethod(context, "length"));
                break;
            case YARVInstructions.OPT_SIZE:
                push(pop().callMethod(context, "size"));
                break;
            case YARVInstructions.OPT_SUCC:
                push(pop().callMethod(context, "succ"));
                break;
            case YARVInstructions.OPT_NOT:
                push(pop().isTrue() ? runtime.getFalse() : runtime.getTrue());
                break;
            case YARVInstructions.OPT_REGEXPMATCH1:
                push(bytecodes[ip].o_op0.callMethod(context, "=~", peek()));
                break;
            case YARVInstructions.OPT_REGEXPMATCH2:
                other = pop();
                push(pop().callMethod(context, "=~", other));
                break;
            case YARVInstructions.ANSWER:
                push(runtime.newFixnum(42));
                break;
            case YARVInstructions.TRACE:
                // System.err.println("Trace: " + bytecodes[ip].l_op0);
                break;
            case YARVInstructions.THROW: {
                IRubyObject throwObj = pop();
                switch ((int) bytecodes[ip].l_op0) {
                case YARVInstructions.RUBY_TAG_RETURN:
                    throw context.returnJump(throwObj);
                case YARVInstructions.RUBY_TAG_BREAK:
                    RuntimeHelpers.breakJump(context, throwObj);
                default:
                    unimplemented(bytecodes[ip].bytecode);
                }
                break;
            }

            default:
                unimplemented(bytecodes[ip].bytecode);
                break;
            }
            ip++;
        }

        return pop();
    }

    public static void callTraceFunction(Ruby runtime, ThreadContext context, RubyEvent event) {
        String name = context.getFrameName();
        RubyModule type = context.getFrameKlazz();
        runtime.callEventHooks(context, event, context.getFile(), context.getLine(), name, type);
    }

    private void op_plus(Ruby runtime, ThreadContext context, IRubyObject other,
            IRubyObject receiver) {
        if (other instanceof RubyFixnum && receiver instanceof RubyFixnum) {
            long receiverValue = ((RubyFixnum) receiver).getLongValue();
            long otherValue = ((RubyFixnum) other).getLongValue();
            long result = receiverValue + otherValue;
            if ((~(receiverValue ^ otherValue) & (receiverValue ^ result) & RubyFixnum.SIGN_BIT) != 0) {
                push(RubyBignum.newBignum(runtime, receiverValue).op_plus(context, other));
            } else {
                push(runtime.newFixnum(result));
            }
        } else {
            push(receiver.callMethod(context, "+", other));
        }
    }

    private void op_minus(Ruby runtime, ThreadContext context, IRubyObject other,
            IRubyObject receiver) {
        if (other instanceof RubyFixnum && receiver instanceof RubyFixnum) {
            long receiverValue = ((RubyFixnum) receiver).getLongValue();
            long otherValue = ((RubyFixnum) other).getLongValue();
            long result = receiverValue - otherValue;
            if ((~(receiverValue ^ otherValue) & (receiverValue ^ result) & RubyFixnum.SIGN_BIT) != 0) {
                push(RubyBignum.newBignum(runtime, receiverValue).op_minus(context, other));
            } else {
                push(runtime.newFixnum(result));
            }
        } else {
            push(receiver.callMethod(context, "-", other));
        }
    }

    private void op_lt(Ruby runtime, ThreadContext context, IRubyObject other, IRubyObject receiver) {
        if (other instanceof RubyFixnum && receiver instanceof RubyFixnum) {
            long receiverValue = ((RubyFixnum) receiver).getLongValue();
            long otherValue = ((RubyFixnum) other).getLongValue();

            push(runtime.newBoolean(receiverValue < otherValue));
        } else {
            push(receiver.callMethod(context, "<", other));
        }
    }

    private void op_gt(Ruby runtime, ThreadContext context, IRubyObject other, IRubyObject receiver) {
        if (other instanceof RubyFixnum && receiver instanceof RubyFixnum) {
            long receiverValue = ((RubyFixnum) receiver).getLongValue();
            long otherValue = ((RubyFixnum) other).getLongValue();

            push(runtime.newBoolean(receiverValue > otherValue));
        } else {
            push(receiver.callMethod(context, ">", other));
        }
    }

    private int send(Ruby runtime, ThreadContext context, IRubyObject self,
            Instruction[] bytecodes, int stackStart, int ip) {
        Instruction instruction = bytecodes[ip];
        String name = instruction.s_op0;
        int size = instruction.i_op1;
        int flags = instruction.i_op3;

        Block block = null;

        // ENEBO: We need to define a YarvBlock
        // Instruction[] blockBytecodes = bytecodes[ip].ins_op;
        // TODO: block stuff
        InstructionSequence blockIseq = bytecodes[ip].iseq_op;
        if (blockIseq != null) {
            // System.err.println("block support not implemented");

            // TODO argumentType array (for lambdas?)
            boolean opts = blockIseq.getOptArgsLength() > 0 || blockIseq.args_rest > 0;
            boolean req = blockIseq.args_argc > 0;
            Arity arity;
            int argumentType = BlockBody.MULTIPLE_ASSIGNMENT;
            if (!req && !opts) {
                arity = Arity.noArguments();
                argumentType = BlockBody.ZERO_ARGS;
            } else if (req && !opts) {
                arity = Arity.fixed(blockIseq.args_argc);
            } else if (opts && !req) {
                arity = Arity.optional();
                if (blockIseq.args_rest > 0 && blockIseq.getOptArgsLength() <= 0) {
                    argumentType = BlockBody.SINGLE_RESTARG;
                }
            } else {
                arity = Arity.required(blockIseq.args_argc);
            }

            StaticScope scope = runtime.getStaticScopeFactory().newBlockScope(
                    context.getCurrentStaticScope());
            scope.setVariables(blockIseq.locals);
            scope.determineModule();
            // TODO when evaluating method call, iteration has to proceed and
// set argument variables accordingly.
            BlockBody blockBody = new YARVBlockBody(scope, arity, argumentType, blockIseq);

            Binding binding = context.currentBinding(self, Visibility.PUBLIC);

            block = new Block(blockBody, binding);
        } else if ((flags & YARVInstructions.ARGS_BLOCKARG_FLAG) != 0) {
            System.err.println("block arg support not implemented");
        }

        if ((flags & YARVInstructions.ARGS_SPLAT_FLAG) != 0) {
            RubyArray splatArray = (RubyArray) pop();
            size += splatArray.getLength() - 1;
            pushArray(splatArray);
        }

        IRubyObject[] args;
        if (size == 0) {
            args = IRubyObject.NULL_ARRAY;
        } else {
            args = new IRubyObject[size];
            popArray(args);
        }

        // FCalls and VCalls use a nil as a place holder, but this is just extra
// stack
        // traffic. Also extra flag activity (tiny perf-wise). I would think
// three
        // send instructions makes more sense...
        IRubyObject recv;
        // CallType callType;
        if ((flags & YARVInstructions.VCALL_FLAG) == 0) {
            if ((flags & YARVInstructions.FCALL_FLAG) == 0) {
                recv = pop();
                // callType = CallType.NORMAL;
                if (instruction.callAdapter == null) {
                    instruction.callAdapter = MethodIndex.getCallSite(name.intern());
                }
            } else {
                pop();
                recv = self;
                // callType = CallType.FUNCTIONAL;
                if (instruction.callAdapter == null) {
                    instruction.callAdapter = MethodIndex.getFunctionalCallSite(name.intern());
                }

            }
        } else {
            pop();
            recv = self;
            // callType = CallType.VARIABLE;
            if (instruction.callAdapter == null) {
                instruction.callAdapter = MethodIndex.getVariableCallSite(name.intern());
            }
        }

        if (TAILCALL_OPT
                && (bytecodes[ip + 1].bytecode == YARVInstructions.LEAVE || (flags & YARVInstructions.TAILCALL_FLAG) == YARVInstructions.TAILCALL_FLAG)
                && recv == self && name.equals(context.getFrameName())) {
            stackTop = stackStart;
            ip = -1;

            for (int i = 0; i < args.length; i++) {
                context.getCurrentScope().getValues()[i] = args[i];
            }
        } else {
            if (block == null) {
                push(instruction.callAdapter.call(context, self, recv, args));
            } else {
                push(instruction.callAdapter.call(context, self, recv, args, block));
            }
            // push(recv.callMethod(context, name, args, callType));
        }

        return ip;
    }
}
