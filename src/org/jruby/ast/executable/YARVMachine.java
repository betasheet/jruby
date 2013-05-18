package org.jruby.ast.executable;

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

    public static ThreadLocal<YARVMachine> INSTANCE = new ThreadLocal<YARVMachine>() {
        @Override
        protected YARVMachine initialValue() {
            return new YARVMachine();
        }
    };

    public static YARVMachine getInstance() {
        return INSTANCE.get();
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
        public YARVBlockBody blockBody;

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
            this.s_op0 = op;
        }

        public Instruction(int bytecode, String op, InstructionSequence op1) {
            this.bytecode = bytecode;
            this.s_op0 = op;
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
        switch (arr.length) {
        case 3:
            arr[2] = stack[stackTop + 2];
        case 2:
            arr[1] = stack[stackTop + 1];
        case 1:
            arr[0] = stack[stackTop];
            break;
        default:
            System.arraycopy(stack, stackTop, arr, 0, arr.length);
            break;
        }

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

        Instruction[] bytecodes = iseq.body;

        // Where this frames stack begins.
        int stackStart = stackTop;
        int ip = 0;
        // IRubyObject other;

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
                int idx;
                if (bytecodes[ip].i_op1 >= 0) {
                    idx = bytecodes[ip].i_op1;
                } else {
                    idx = scope.getStaticScope().getNumberOfVariables() - (int) bytecodes[ip].l_op0;
                    bytecodes[ip].i_op1 = idx;
                }
                push(scope.getValue(idx, 0));
                break;
            }
            case YARVInstructions.SETLOCAL: {
                DynamicScope scope = context.getCurrentScope().localScope;
                int idx;
                if (bytecodes[ip].i_op1 >= 0) {
                    idx = bytecodes[ip].i_op1;
                } else {
                    idx = scope.getStaticScope().getNumberOfVariables() - (int) bytecodes[ip].l_op0;
                    bytecodes[ip].i_op1 = idx;
                }
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
                IRubyObject value = pop();
                if (klass == null || klass == runtime.getNil()) {
                    context.getCurrentStaticScope().setConstant(bytecodes[ip].s_op0, value);
                    runtime.incGlobalState();
                } else {
                    push(((RubyModule) klass).setConstant(bytecodes[ip].s_op0, value));
                    runtime.incGlobalState();
                }
                break;
            }
            case YARVInstructions.PUTNIL:
                push(runtime.getNil());
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
                    push(runtime.getYarvVMCore());
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
                push(runtime.newString(bytecodes[ip].s_op0));
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
                        push(array.eltInternal(i));
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
            case YARVInstructions.NEWHASH: {
                int hsize = (int) bytecodes[ip].l_op0;
                RubyHash h = RubyHash.newHash(runtime);
                IRubyObject v, k;
                for (int i = hsize; i > 0; i -= 2) {
                    v = pop();
                    k = pop();
                    h.op_aset(context, k, v);
                }
                push(h);
                break;
            }
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
                // op_plus(runtime, context, self, pop(), pop());
                sendVirtual1Arg(runtime, context, bytecodes[ip], self, "+");
                break;
            case YARVInstructions.OPT_MINUS:
                // op_minus(runtime, context, self, pop(), pop());
                sendVirtual1Arg(runtime, context, bytecodes[ip], self, "-");
                break;
            case YARVInstructions.OPT_MULT:
                sendVirtual1Arg(runtime, context, bytecodes[ip], self, "*");
                break;
            case YARVInstructions.OPT_DIV:
                sendVirtual1Arg(runtime, context, bytecodes[ip], self, "/");
                break;
            case YARVInstructions.OPT_MOD:
                sendVirtual1Arg(runtime, context, bytecodes[ip], self, "%");
                break;
            case YARVInstructions.OPT_EQ:
                sendVirtual1Arg(runtime, context, bytecodes[ip], self, "==");
                break;
            case YARVInstructions.OPT_NEQ:
                sendVirtual1Arg(runtime, context, bytecodes[ip], self, "!=");
                break;
            case YARVInstructions.OPT_LT:
                // op_lt(runtime, context, self, pop(), pop());
                sendVirtual1Arg(runtime, context, bytecodes[ip], self, "<");
                break;
            case YARVInstructions.OPT_LE:
                sendVirtual1Arg(runtime, context, bytecodes[ip], self, "<=");
                break;
            case YARVInstructions.OPT_LTLT:
                sendVirtual1Arg(runtime, context, bytecodes[ip], self, "<<");
                break;
            case YARVInstructions.OPT_GT:
                // op_gt(runtime, context, self, pop(), pop());
                sendVirtual1Arg(runtime, context, bytecodes[ip], self, ">");
                break;
            case YARVInstructions.OPT_GE:
                sendVirtual1Arg(runtime, context, bytecodes[ip], self, ">=");
                break;
            case YARVInstructions.OPT_AREF:
                sendVirtual1Arg(runtime, context, bytecodes[ip], self, "[]");
                break;
            case YARVInstructions.OPT_ASET: {
                // YARV will never emit this, for some reason.
                // IRubyObject value = pop();
                // other = pop();
                // push(RuntimeHelpers.invoke(context, pop(), "[]=", other,
// value));
                sendVirtual2Args(runtime, context, bytecodes[ip], self, "[]=");
                break;
            }
            case YARVInstructions.OPT_LENGTH:
                sendVirtual0Args(runtime, context, bytecodes[ip], self, "length");
                break;
            case YARVInstructions.OPT_SIZE:
                sendVirtual0Args(runtime, context, bytecodes[ip], self, "size");
                break;
            case YARVInstructions.OPT_SUCC:
                sendVirtual0Args(runtime, context, bytecodes[ip], self, "succ");
                break;
            case YARVInstructions.OPT_NOT:
                push(pop().isTrue() ? runtime.getFalse() : runtime.getTrue());
                break;
            case YARVInstructions.OPT_REGEXPMATCH1:
                sendVirtual1Arg(runtime, context, bytecodes[ip], self, "=~", bytecodes[ip].o_op0,
                        peek());
                // push(bytecodes[ip].o_op0.callMethod(context, "=~", peek()));
                break;
            case YARVInstructions.OPT_REGEXPMATCH2:
                sendVirtual1Arg(runtime, context, bytecodes[ip], self, "=~");
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

    private void op_plus(Ruby runtime, ThreadContext context, Instruction instr, IRubyObject self,
            IRubyObject other, IRubyObject receiver) {
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
            sendVirtual1Arg(runtime, context, instr, self, "+", receiver, other);
            // push(receiver.callMethod(context, "+", other));
        }
    }

    private void op_minus(Ruby runtime, ThreadContext context, Instruction instr, IRubyObject self,
            IRubyObject other, IRubyObject receiver) {
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
            sendVirtual1Arg(runtime, context, instr, self, "-", receiver, other);
            // push(receiver.callMethod(context, "-", other));
        }
    }

    private void op_lt(Ruby runtime, ThreadContext context, Instruction instr, IRubyObject self,
            IRubyObject other, IRubyObject receiver) {
        if (other instanceof RubyFixnum && receiver instanceof RubyFixnum) {
            long receiverValue = ((RubyFixnum) receiver).getLongValue();
            long otherValue = ((RubyFixnum) other).getLongValue();

            push(runtime.newBoolean(receiverValue < otherValue));
        } else {
            sendVirtual1Arg(runtime, context, instr, self, "<", receiver, other);
            // push(receiver.callMethod(context, "<", other));
        }
    }

    private void op_gt(Ruby runtime, ThreadContext context, Instruction instr, IRubyObject self,
            IRubyObject other, IRubyObject receiver) {
        if (other instanceof RubyFixnum && receiver instanceof RubyFixnum) {
            long receiverValue = ((RubyFixnum) receiver).getLongValue();
            long otherValue = ((RubyFixnum) other).getLongValue();

            push(runtime.newBoolean(receiverValue > otherValue));
        } else {
            sendVirtual1Arg(runtime, context, instr, self, ">", receiver, other);
            // push(receiver.callMethod(context, ">", other));
        }
    }

    private int send(Ruby runtime, ThreadContext context, IRubyObject self,
            Instruction[] bytecodes, int stackStart, int ip) {
        Instruction instruction = bytecodes[ip];
        String name = instruction.s_op0;
        int size = instruction.i_op1;
        int flags = instruction.i_op3;

        Block block = null;

        InstructionSequence blockIseq = bytecodes[ip].iseq_op;
        if (blockIseq != null) {
            // System.err.println("block support not implemented");

            if (blockIseq.blockBody == null) {
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
                // TODO when evaluating method call, iteration has to proceed
// and set argument variables accordingly.
                blockIseq.blockBody = new YARVBlockBody(scope, arity, argumentType, blockIseq);
            }

            blockIseq.blockBody.getStaticScope().determineModule();
            Binding binding = context.currentBinding(self, Visibility.PUBLIC);

            block = new Block(blockIseq.blockBody, binding);
        } else if ((flags & YARVInstructions.ARGS_BLOCKARG_FLAG) != 0) {
            System.err.println("block arg support not implemented");
        }

        if (instruction.callAdapter == null) {
            if ((flags & YARVInstructions.VCALL_FLAG) == 0) {
                if ((flags & YARVInstructions.FCALL_FLAG) == 0) {
                    instruction.callAdapter = MethodIndex.getCallSite(name);
                } else {
                    instruction.callAdapter = MethodIndex.getFunctionalCallSite(name);

                }
            } else {
                instruction.callAdapter = MethodIndex.getVariableCallSite(name);
            }
        }

        if ((flags & YARVInstructions.ARGS_SPLAT_FLAG) != 0) {
            RubyArray splatArray = (RubyArray) pop();
            size += splatArray.getLength() - 1;
            pushArray(splatArray);
        }

        switch (size) {
        case 3: {
            IRubyObject arg3 = pop();
            IRubyObject arg2 = pop();
            IRubyObject arg1 = pop();

            IRubyObject recv = pop();
            if (TAILCALL_OPT && isTailCall(context, bytecodes, flags, recv, self, flags, name)) {
                stackTop = stackStart;
                ip = -1;

                IRubyObject[] vals = context.getCurrentScope().getValues();
                vals[0] = arg1;
                vals[1] = arg2;
                vals[2] = arg3;
            } else {
                if (block == null) {
                    push(instruction.callAdapter.call(context, self, recv, arg1, arg2, arg3));
                } else {
                    push(instruction.callAdapter.call(context, self, recv, arg1, arg2, arg3, block));
                }
            }
            break;
        }
        case 2: {
            IRubyObject arg2 = pop();
            IRubyObject arg1 = pop();

            IRubyObject recv = pop();
            if (TAILCALL_OPT && isTailCall(context, bytecodes, flags, recv, self, flags, name)) {
                stackTop = stackStart;
                ip = -1;

                IRubyObject[] vals = context.getCurrentScope().getValues();
                vals[0] = arg1;
                vals[1] = arg2;
            } else {
                if (block == null) {
                    push(instruction.callAdapter.call(context, self, recv, arg1, arg2));
                } else {
                    push(instruction.callAdapter.call(context, self, recv, arg1, arg2, block));
                }
            }
            break;
        }
        case 1: {
            IRubyObject arg1 = pop();

            IRubyObject recv = pop();
            if (TAILCALL_OPT && isTailCall(context, bytecodes, flags, recv, self, flags, name)) {
                stackTop = stackStart;
                ip = -1;

                IRubyObject[] vals = context.getCurrentScope().getValues();
                vals[0] = arg1;
            } else {
                if (block == null) {
                    push(instruction.callAdapter.call(context, self, recv, arg1));
                } else {
                    push(instruction.callAdapter.call(context, self, recv, arg1, block));
                }
            }
            break;
        }
        case 0: {
            IRubyObject recv = pop();
            if (TAILCALL_OPT && isTailCall(context, bytecodes, flags, recv, self, flags, name)) {
                stackTop = stackStart;
                ip = -1;
            } else {
                if (block == null) {
                    push(instruction.callAdapter.call(context, self, recv));
                } else {
                    push(instruction.callAdapter.call(context, self, recv, block));
                }
            }
            break;
        }
        default: {
            IRubyObject[] args;
            args = new IRubyObject[size];
            popArray(args);

            IRubyObject recv = pop();
            if (TAILCALL_OPT && isTailCall(context, bytecodes, flags, recv, self, flags, name)) {
                stackTop = stackStart;
                ip = -1;

                IRubyObject[] vals = context.getCurrentScope().getValues();
                for (int i = 0; i < size; i++) {
                    vals[i] = args[i];
                }
            } else {
                if (block == null) {
                    push(instruction.callAdapter.call(context, self, recv, args));
                } else {
                    push(instruction.callAdapter.call(context, self, recv, args, block));
                }
            }
            break;
        }
        }

        return ip;
    }

    private boolean isTailCall(ThreadContext context, Instruction[] bytecodes, int ip,
            IRubyObject recv, IRubyObject self, int flags, String name) {
        return (bytecodes[ip + 1].bytecode == YARVInstructions.LEAVE || (flags & YARVInstructions.TAILCALL_FLAG) == YARVInstructions.TAILCALL_FLAG)
                && recv == self && name.equals(context.getFrameName());
    }

    private void sendVirtual(Ruby runtime, ThreadContext context, Instruction instr,
            IRubyObject self, String name, int size) {
        if (size == 3) {
            sendVirtual3Args(runtime, context, instr, self, name);
        } else if (size == 2) {
            sendVirtual2Args(runtime, context, instr, self, name);
        } else if (size == 1) {
            sendVirtual1Arg(runtime, context, instr, self, name);
        } else if (size == 0) {
            sendVirtual0Args(runtime, context, instr, self, name);
        } else {
            sendVirtualManyArgs(runtime, context, instr, self, name, size);
        }
    }

    private void sendVirtual0Args(Ruby runtime, ThreadContext context, Instruction instr,
            IRubyObject self, String name) {
        if (instr.callAdapter == null) {
            instr.callAdapter = MethodIndex.getCallSite(name);
        }
        
        push(instr.callAdapter.call(context, self, pop()));
    }

    private void sendVirtual1Arg(Ruby runtime, ThreadContext context, Instruction instr,
            IRubyObject self, String name) {
        if (instr.callAdapter == null) {
            instr.callAdapter = MethodIndex.getCallSite(name);
        }
        
        IRubyObject arg1 = pop();
        push(instr.callAdapter.call(context, self, pop(), arg1));
    }

    private void sendVirtual1Arg(Ruby runtime, ThreadContext context, Instruction instr,
            IRubyObject self, String name, IRubyObject recv, IRubyObject arg1) {
        if (instr.callAdapter == null) {
            instr.callAdapter = MethodIndex.getCallSite(name);
        }
        
        push(instr.callAdapter.call(context, self, recv, arg1));
    }

    private void sendVirtual2Args(Ruby runtime, ThreadContext context, Instruction instr,
            IRubyObject self, String name) {
        if (instr.callAdapter == null) {
            instr.callAdapter = MethodIndex.getCallSite(name);
        }
        
        IRubyObject arg2 = pop();
        IRubyObject arg1 = pop();
        push(instr.callAdapter.call(context, self, pop(), arg1, arg2));
    }

    private void sendVirtual2Args(Ruby runtime, ThreadContext context, Instruction instr,
            IRubyObject self, String name, IRubyObject recv, IRubyObject arg1, IRubyObject arg2) {
        if (instr.callAdapter == null) {
            instr.callAdapter = MethodIndex.getCallSite(name);
        }
        
        push(instr.callAdapter.call(context, self, recv, arg1, arg2));
    }

    private void sendVirtual3Args(Ruby runtime, ThreadContext context, Instruction instr,
            IRubyObject self, String name) {
        if (instr.callAdapter == null) {
            instr.callAdapter = MethodIndex.getCallSite(name);
        }

        IRubyObject arg3 = pop();
        IRubyObject arg2 = pop();
        IRubyObject arg1 = pop();
        push(instr.callAdapter.call(context, self, pop(), arg1, arg2, arg3));
    }

    private void sendVirtual3Args(Ruby runtime, ThreadContext context, Instruction instr,
            IRubyObject self, String name, IRubyObject recv, IRubyObject arg1, IRubyObject arg2,
            IRubyObject arg3) {
        if (instr.callAdapter == null) {
            instr.callAdapter = MethodIndex.getCallSite(name);
        }

        push(instr.callAdapter.call(context, self, recv, arg1, arg2, arg3));
    }

    private void sendVirtualManyArgs(Ruby runtime, ThreadContext context, Instruction instr,
            IRubyObject self, String name, int size) {
        if (instr.callAdapter == null) {
            instr.callAdapter = MethodIndex.getCallSite(name);
        }
        
        IRubyObject[] args;
        if (size == 0) {
            args = IRubyObject.NULL_ARRAY;
        } else {
            args = new IRubyObject[size];
            popArray(args);
        }
        push(instr.callAdapter.call(context, self, pop(), args));
    }

    // TODO caching call sites do not make sense if not stored. (store with
// instruction)?
    // TODO do we need to intern() method names?
}
