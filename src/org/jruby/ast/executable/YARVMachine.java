package org.jruby.ast.executable;

import org.jruby.MetaClass;
import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyBignum;
import org.jruby.RubyClass;
import org.jruby.RubyFixnum;
import org.jruby.RubyHash;
import org.jruby.RubyModule;
import org.jruby.RubyRange;
import org.jruby.RubyRegexp;
import org.jruby.RubyString;
import org.jruby.ast.executable.YARVByteCode.InlineCache;
import org.jruby.javasupport.util.RuntimeHelpers;
import org.jruby.parser.StaticScope;
import org.jruby.runtime.Arity;
import org.jruby.runtime.Binding;
import org.jruby.runtime.Block;
import org.jruby.runtime.BlockBody;
import org.jruby.runtime.CallSite;
import org.jruby.runtime.DynamicScope;
import org.jruby.runtime.MethodIndex;
import org.jruby.runtime.RubyEvent;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.YARVBlockBody;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.runtime.scope.ManyVarsDynamicScope;
import org.jruby.util.ByteList;
import org.jruby.util.RegexpOptions;

public class YARVMachine {

    protected static final boolean TAILCALL_OPT = Boolean.getBoolean("jruby.tailcall.enabled");

    // is set from Ruby instance initialization
    public static boolean threadedCode;
    
    public static final ThreadLocal<YARVMachine> INSTANCE = new ThreadLocal<YARVMachine>() {
        @Override
        protected YARVMachine initialValue() {
            //System.err.println("new yarvmachine");
            return threadedCode ? new YARVThreadedCodeInterpreter() : new YARVMachine();
        }
    };

    public static YARVMachine getInstance() {
        return INSTANCE.get();
    }

    protected IRubyObject[] stack = new IRubyObject[8192];
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
    protected void push(IRubyObject value) {
        // System.out.println("push(" + value.inspect() + ")");
        stack[stackTop] = value;
        stackTop++;
    }

    /**
     * Swap top two values in the stack
     */
    protected void swap() {
        stack[stackTop] = stack[stackTop - 1];
        stack[stackTop - 1] = stack[stackTop - 2];
        stack[stackTop - 2] = stack[stackTop];
    }

    /**
     * Duplicate top 'n' values in the stack
     * 
     * @param length
     */
    protected void dupn(int length) {
        System.arraycopy(stack, stackTop - length, stack, stackTop, length);
        stackTop += length;
    }

    /**
     * Peek at top value in the stack
     * 
     * @return the top value
     */
    protected IRubyObject peek() {
        return stack[stackTop - 1];
    }

    /**
     * pop top value in the stack
     * 
     * @return the top value
     */
    protected IRubyObject pop() {
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
    protected IRubyObject[] popArray(IRubyObject arr[]) {
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
    protected void pushArray(RubyArray arr) {
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
    protected void setn(int depth, IRubyObject value) {
        stack[stackTop - depth - 1] = value;
    }

    /**
     * push nth stack value
     * 
     * @param depth
     *            which element to push
     */
    protected void topn(int depth) {
        push(stack[stackTop - depth - 1]);
    }

    /**
     * Set/Replace top stack value with value
     * 
     * @param value
     *            to replace current stack value
     */
    protected void set(IRubyObject value) {
        stack[stackTop - 1] = value;
    }

    protected void unimplemented(int bytecode) {
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
    public IRubyObject exec(ThreadContext context, StaticScope scope, YARVByteCode byteCode) {
        try {
            IRubyObject self = context.getRuntime().getObject();

            context.preScopedBody(new ManyVarsDynamicScope(scope));

            if (scope.getModule() == null) {
                scope.setModule(context.getRuntime().getObject());
            }

            return exec(context, self, byteCode);
        } finally {
            context.postScopedBody();
        }
    }

    public IRubyObject exec(ThreadContext context, IRubyObject self, YARVByteCode byteCode) {
        Ruby runtime = context.getRuntime();

        byte[] body = byteCode.body;

        // Where this frames stack begins.
        int stackStart = stackTop;
        int ip = 0;
        // IRubyObject other;

        yarvloop: while (ip < body.length) {
            byte opCode = body[ip];
            // System.err.println("Executing: " + YARVInstructions.name(opCode)
// + " (ip=" + ip + ")");
            switch (opCode) {
            case YARVInstructions.NOP:
                ip += 1;
                break;
            case YARVInstructions.GETGLOBAL: {
                String op = (String) YARVByteCode.getConstant(body, ip + 1);
                push(runtime.getGlobalVariables().get(op));
                ip += 5;
                break;
            }
            case YARVInstructions.SETGLOBAL: {
                String op = (String) YARVByteCode.getConstant(body, ip + 1);
                runtime.getGlobalVariables().set(op, pop());
                ip += 5;
                break;
            }
            case YARVInstructions.GETLOCAL: {
                DynamicScope scope = context.getCurrentScope().localScope;
                int idx = YARVByteCode.getInt(body, ip + 1);
                idx = scope.getStaticScope().getNumberOfVariables() - idx;
                push(scope.getValue(idx, 0));
                ip += 5;
                break;
            }
            case YARVInstructions.SETLOCAL: {
                DynamicScope scope = context.getCurrentScope().localScope;
                int idx = YARVByteCode.getInt(body, ip + 1);
                idx = scope.getStaticScope().getNumberOfVariables() - idx;
                scope.setValue(idx, pop(), 0);
                ip += 5;
                break;
            }
            case YARVInstructions.GETDYNAMIC: {
                int depth = YARVByteCode.getInt(body, ip + 5);
                DynamicScope scope = context.getCurrentScope();
                if (depth > 0) {
                    scope = scope.getNthParentScope(depth);
                }
                int idx = scope.getStaticScope().getNumberOfVariables()
                        - YARVByteCode.getInt(body, ip + 1);
                push(scope.getValue(idx, 0));
                ip += 9;
                break;
            }
            case YARVInstructions.SETDYNAMIC: {
                int depth = YARVByteCode.getInt(body, ip + 5);
                DynamicScope scope = context.getCurrentScope();
                if (depth > 0) {
                    scope = scope.getNthParentScope(depth);
                }
                int idx = scope.getStaticScope().getNumberOfVariables()
                        - YARVByteCode.getInt(body, ip + 1);
                scope.setValue(idx, pop(), 0);
                ip += 9;
                break;
            }
            case YARVInstructions.GETINSTANCEVARIABLE: {
                String op = (String) YARVByteCode.getConstant(body, ip + 1);
                push(self.getInstanceVariables().getInstanceVariable(op));
                ip += 5;
                break;
            }
            case YARVInstructions.SETINSTANCEVARIABLE: {
                String op = (String) YARVByteCode.getConstant(body, ip + 1);
                self.getInstanceVariables().setInstanceVariable(op, pop());
                ip += 5;
                break;
            }
            case YARVInstructions.GETCLASSVARIABLE: {
                RubyModule rubyClass = context.getRubyClass();
                String name = (String) YARVByteCode.getConstant(body, ip + 1);

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
                ip += 5;
                break;
            }
            case YARVInstructions.SETCLASSVARIABLE: {
                RubyModule rubyClass = context.getCurrentScope().getStaticScope().getModule();
                String name = (String) YARVByteCode.getConstant(body, ip + 1);

                if (rubyClass == null) {
                    rubyClass = self.getMetaClass();
                } else if (rubyClass.isSingleton()) {
                    rubyClass = (RubyModule) (((MetaClass) rubyClass).getAttached());
                }

                rubyClass.setClassVar(name, pop());
                ip += 5;
                break;
            }
            case YARVInstructions.GETCONSTANT: {
                String op = (String) YARVByteCode.getConstant(body, ip + 1);
                IRubyObject klass = pop();
                if (klass == null || klass == runtime.getNil()) {
                    push(context.getCurrentStaticScope().getConstant(op));
                } else {
                    push(((RubyModule) klass).getConstant(op));
                }
                ip += 5;
                break;
            }
            case YARVInstructions.SETCONSTANT: {
                String op = (String) YARVByteCode.getConstant(body, ip + 1);
                IRubyObject klass = pop();
                IRubyObject value = pop();
                if (klass == null || klass == runtime.getNil()) {
                    context.getCurrentStaticScope().setConstant(op, value);
                    runtime.incGlobalState();
                } else {
                    push(((RubyModule) klass).setConstant(op, value));
                    runtime.incGlobalState();
                }
                ip += 5;
                break;
            }
            case YARVInstructions.PUTNIL:
                push(runtime.getNil());
                ip += 1;
                break;
            case YARVInstructions.PUTSELF:
                push(self);
                ip += 1;
                break;
            case YARVInstructions.PUTISEQ:
            case YARVInstructions.PUTOBJECT: {
                IRubyObject op = (IRubyObject) YARVByteCode.getConstant(body, ip + 1);
                push(op);
                ip += 5;
                break;
            }
            case YARVInstructions.PUTSPECIALOBJECT: {
                // TODO cbase / const base difference (put by eval?
// vm_insnhelper.c)
                int op = YARVByteCode.getInt(body, ip + 1);
                if (op == 1) { // VM_SPECIAL_OBJECT_VMCORE
                    push(runtime.getYarvVMCore());
                } else if (op == 2) { // VM_SPECIAL_OBJECT_CBASE
                    push(context.getRubyClass());
                } else if (op == 3) { // VM_SPECIAL_OBJECT_CONST_BASE
                    push(context.getRubyClass());
                } else {
                    unimplemented(YARVInstructions.PUTSPECIALOBJECT);
                }
                ip += 5;
                break;
            }
            case YARVInstructions.DEFINECLASS: {
                IRubyObject parentClass = pop();
                IRubyObject cBase = pop();
                String name = (String) YARVByteCode.getConstant(body, ip + 1);
                YARVByteCode bc = (YARVByteCode) YARVByteCode.getConstant(body, ip + 5);
                int type = YARVByteCode.getInt(body, ip + 9);

                boolean isRedefine = (parentClass == runtime.getFalse());

                switch (type) {
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
                    sco.setVariables(bc.locals);
                    sco.setModule(newClass);

                    context.preClassEval(sco, newClass);

                    try {
                        if (runtime.hasEventHooks()) {
                            callTraceFunction(runtime, context, RubyEvent.CLASS);
                        }

                        YARVMachine.getInstance().exec(context, newClass, bc);
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
                ip += 13;
                break;
            }
            case YARVInstructions.PUTSTRING: {
                String op = (String) YARVByteCode.getConstant(body, ip + 1);
                push(runtime.newString(op));
                ip += 5;
                break;
            }
            case YARVInstructions.CONCATSTRINGS: {
                int op = YARVByteCode.getInt(body, ip + 1);
                StringBuilder concatter = new StringBuilder();

                for (int i = (int) (stackTop - op); i < stackTop; i++) {
                    concatter.append(stack[i].toString());
                }
                stackTop -= op;

                push(runtime.newString(concatter.toString()));
                ip += 5;
                break;
            }
            case YARVInstructions.TOSTRING:
                IRubyObject top = peek();
                if (!(top instanceof RubyString)) {
                    set(top.callMethod(context, "to_s"));
                }
                ip += 1;
                break;
            case YARVInstructions.TOREGEXP: {
                int options = YARVByteCode.getInt(body, ip + 1);
                int count = YARVByteCode.getInt(body, ip + 5);
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
                push(RubyRegexp.newRegexp(runtime, pattern, RegexpOptions.fromJoniOptions(options)));
                ip += 9;
                break;
            }
            case YARVInstructions.NEWARRAY: {
                int op = YARVByteCode.getInt(body, ip + 1);
                push(runtime.newArrayNoCopy(popArray(new IRubyObject[op])));
                ip += 5;
                break;
            }
            case YARVInstructions.DUPARRAY: {
                IRubyObject op = (IRubyObject) YARVByteCode.getConstant(body, ip + 1);
                push(op.dup());
                ip += 5;
                break;
            }
            case YARVInstructions.EXPANDARRAY: {
                int op = YARVByteCode.getInt(body, ip + 1);
                int flag = YARVByteCode.getInt(body, ip + 5);
                IRubyObject ary = pop();
                if (ary != null && ary instanceof RubyArray) {
                    RubyArray array = (RubyArray) ary;
                    // for (int i = 0; i < ((int) bytecodes[ip].l_op0); i++) {
                    for (int i = op - 1; i >= 0; i--) {
                        push(array.eltInternal(i));
                    }
                    // TODO support for flag
                } else {
                    push(ary);
                    for (int i = 1; i < op; i++) {
                        push(runtime.getNil());
                    }
                }
                ip += 9;
                break;
            }
            case YARVInstructions.NEWHASH: {
                int hsize = YARVByteCode.getInt(body, ip + 1);
                RubyHash h = RubyHash.newHash(runtime);
                IRubyObject v, k;
                for (int i = hsize; i > 0; i -= 2) {
                    v = pop();
                    k = pop();
                    h.op_aset(context, k, v);
                }
                push(h);
                ip += 5;
                break;
            }
            case YARVInstructions.NEWRANGE: {
                // high, low, flag
                int op = YARVByteCode.getInt(body, ip + 1);
                IRubyObject end = pop();
                IRubyObject begin = pop();
                push(RubyRange.newRange(runtime, context, begin, end, op != 0));
                ip += 5;
                break;
            }
            case YARVInstructions.POP:
                pop();
                ip += 1;
                break;
            case YARVInstructions.DUP:
                push(peek());
                ip += 1;
                break;
            case YARVInstructions.DUPN: {
                int op = YARVByteCode.getInt(body, ip + 1);
                dupn(op);
                ip += 5;
                break;
            }
            case YARVInstructions.SWAP:
                swap();
                ip += 1;
                break;
            case YARVInstructions.TOPN: {
                int op = YARVByteCode.getInt(body, ip + 1);
                topn(op);
                ip += 5;
                break;
            }
            case YARVInstructions.SETN: {
                int op = YARVByteCode.getInt(body, ip + 1);
                setn(op, peek());
                ip += 5;
                break;
            }
            case YARVInstructions.SEND: {
                String name = (String) YARVByteCode.getConstant(body, ip + 1);
                int size = YARVByteCode.getInt(body, ip + 5);
                YARVByteCode blockByteCode = (YARVByteCode) YARVByteCode.getConstant(body, ip + 9);
                int flags = YARVByteCode.getInt(body, ip + 13);
                int icId = YARVByteCode.getInt(body, ip + 17);
                InlineCache ic = byteCode.getInlineCache(icId);
                ip += 21;
                ip = send(runtime, context, self, name, size, blockByteCode, flags, ic, body,
                        stackStart, ip);
                break;
            }
            case YARVInstructions.LEAVE:
                break yarvloop;
            case YARVInstructions.JUMP:
                ip = YARVByteCode.getInt(body, ip + 1);
                continue yarvloop;
            case YARVInstructions.BRANCHIF:
                ip = pop().isTrue() ? YARVByteCode.getInt(body, ip + 1) : ip + 5;
                continue yarvloop;
            case YARVInstructions.BRANCHUNLESS: {
                ip = !pop().isTrue() ? YARVByteCode.getInt(body, ip + 1) : ip + 5;
                continue yarvloop;
            }
            case YARVInstructions.ONCEINLINECACHE:
            case YARVInstructions.GETINLINECACHE: {
                int op = YARVByteCode.getInt(body, ip + 1);
                int icId = YARVByteCode.getInt(body, ip + 5);
                InlineCache ic = byteCode.getInlineCache(icId);
                Object cachedObject;
                if ((cachedObject = ic.get(runtime.getGlobalState())) != null) {
                    push((IRubyObject) cachedObject);
                    ip = op;
                    continue yarvloop;
                }
                push(runtime.getNil());
                ip += 9;
                break;
            }
            case YARVInstructions.SETINLINECACHE: {
                int op = YARVByteCode.getInt(body, ip + 1);
                InlineCache ic = byteCode.getInlineCache(op);
                ic.update(runtime.getGlobalState(), peek());
                ip += 5;
                break;
            }
            case YARVInstructions.OPT_PLUS: {
                // op_plus(runtime, context, self, pop(), pop());
                int op = YARVByteCode.getInt(body, ip + 1);
                InlineCache ic = byteCode.getInlineCache(op);
                sendVirtual1Arg(runtime, context, ic, self, "+");
                ip += 5;
                break;
            }
            case YARVInstructions.OPT_MINUS: {
                // op_minus(runtime, context, self, pop(), pop());
                int op = YARVByteCode.getInt(body, ip + 1);
                InlineCache ic = byteCode.getInlineCache(op);
                sendVirtual1Arg(runtime, context, ic, self, "-");
                ip += 5;
                break;
            }
            case YARVInstructions.OPT_MULT: {
                int op = YARVByteCode.getInt(body, ip + 1);
                InlineCache ic = byteCode.getInlineCache(op);
                sendVirtual1Arg(runtime, context, ic, self, "*");
                ip += 5;
                break;
            }
            case YARVInstructions.OPT_DIV: {
                int op = YARVByteCode.getInt(body, ip + 1);
                InlineCache ic = byteCode.getInlineCache(op);
                sendVirtual1Arg(runtime, context, ic, self, "/");
                ip += 5;
                break;
            }
            case YARVInstructions.OPT_MOD: {
                int op = YARVByteCode.getInt(body, ip + 1);
                InlineCache ic = byteCode.getInlineCache(op);
                sendVirtual1Arg(runtime, context, ic, self, "%");
                ip += 5;
                break;
            }
            case YARVInstructions.OPT_EQ: {
                int op = YARVByteCode.getInt(body, ip + 1);
                InlineCache ic = byteCode.getInlineCache(op);
                sendVirtual1Arg(runtime, context, ic, self, "==");
                ip += 5;
                break;
            }
            case YARVInstructions.OPT_NEQ: {
                int op = YARVByteCode.getInt(body, ip + 1);
                InlineCache ic = byteCode.getInlineCache(op);
                sendVirtual1Arg(runtime, context, ic, self, "!=");
                ip += 5;
                break;
            }
            case YARVInstructions.OPT_LT: {
                // op_lt(runtime, context, self, pop(), pop());
                int op = YARVByteCode.getInt(body, ip + 1);
                InlineCache ic = byteCode.getInlineCache(op);
                sendVirtual1Arg(runtime, context, ic, self, "<");
                ip += 5;
                break;
            }
            case YARVInstructions.OPT_LE: {
                int op = YARVByteCode.getInt(body, ip + 1);
                InlineCache ic = byteCode.getInlineCache(op);
                sendVirtual1Arg(runtime, context, ic, self, "<=");
                ip += 5;
                break;
            }
            case YARVInstructions.OPT_LTLT: {
                int op = YARVByteCode.getInt(body, ip + 1);
                InlineCache ic = byteCode.getInlineCache(op);
                sendVirtual1Arg(runtime, context, ic, self, "<<");
                ip += 5;
                break;
            }
            case YARVInstructions.OPT_GT: {
                // op_gt(runtime, context, self, pop(), pop());
                int op = YARVByteCode.getInt(body, ip + 1);
                InlineCache ic = byteCode.getInlineCache(op);
                sendVirtual1Arg(runtime, context, ic, self, ">");
                ip += 5;
                break;
            }
            case YARVInstructions.OPT_GE: {
                int op = YARVByteCode.getInt(body, ip + 1);
                InlineCache ic = byteCode.getInlineCache(op);
                sendVirtual1Arg(runtime, context, ic, self, ">=");
                ip += 5;
                break;
            }
            case YARVInstructions.OPT_AREF: {
                int op = YARVByteCode.getInt(body, ip + 1);
                InlineCache ic = byteCode.getInlineCache(op);
                sendVirtual1Arg(runtime, context, ic, self, "[]");
                ip += 5;
                break;
            }
            case YARVInstructions.OPT_ASET: {
                // YARV will never emit this, for some reason.
                // IRubyObject value = pop();
                // other = pop();
                // push(RuntimeHelpers.invoke(context, pop(), "[]=", other,
// value));
                int op = YARVByteCode.getInt(body, ip + 1);
                InlineCache ic = byteCode.getInlineCache(op);
                sendVirtual2Args(runtime, context, ic, self, "[]=");
                ip += 5;
                break;
            }
            case YARVInstructions.OPT_LENGTH: {
                int op = YARVByteCode.getInt(body, ip + 1);
                InlineCache ic = byteCode.getInlineCache(op);
                sendVirtual0Args(runtime, context, ic, self, "length");
                ip += 5;
                break;
            }
            case YARVInstructions.OPT_SIZE: {
                int op = YARVByteCode.getInt(body, ip + 1);
                InlineCache ic = byteCode.getInlineCache(op);
                sendVirtual0Args(runtime, context, ic, self, "size");
                ip += 5;
                break;
            }
            case YARVInstructions.OPT_SUCC: {
                int op = YARVByteCode.getInt(body, ip + 1);
                InlineCache ic = byteCode.getInlineCache(op);
                sendVirtual0Args(runtime, context, ic, self, "succ");
                ip += 5;
                break;
            }
            case YARVInstructions.OPT_NOT: {
                push(pop().isTrue() ? runtime.getFalse() : runtime.getTrue());
                ip += 5;
                break;
            }
            case YARVInstructions.OPT_REGEXPMATCH1: {
                int op = YARVByteCode.getInt(body, ip + 1);
                InlineCache ic = byteCode.getInlineCache(op);
                IRubyObject op1 = (IRubyObject) YARVByteCode.getConstant(body, ip + 5);
                sendVirtual1Arg(runtime, context, ic, self, "=~", op1, peek());
                // push(bytecodes[ip].o_op0.callMethod(context, "=~", peek()));
                ip += 9;
                break;
            }
            case YARVInstructions.OPT_REGEXPMATCH2: {
                int op = YARVByteCode.getInt(body, ip + 1);
                InlineCache ic = byteCode.getInlineCache(op);
                sendVirtual1Arg(runtime, context, ic, self, "=~");
                ip += 5;
                break;
            }
            case YARVInstructions.ANSWER: {
                push(runtime.newFixnum(42));
                ip += 1;
                break;
            }
            case YARVInstructions.TRACE:
                // System.err.println("Trace: " + bytecodes[ip].l_op0);
                ip += 5;
                break;
            case YARVInstructions.THROW: {
                int op = YARVByteCode.getInt(body, ip + 1);
                IRubyObject throwObj = pop();
                switch (op) {
                case YARVInstructions.RUBY_TAG_RETURN:
                    throw context.returnJump(throwObj);
                case YARVInstructions.RUBY_TAG_BREAK:
                    RuntimeHelpers.breakJump(context, throwObj);
                default:
                    unimplemented(opCode);
                }
                ip += 5;
                break;
            }

            default:
                unimplemented(opCode);
                ip += 1;
                break;
            }
        }

        return pop();
    }

    public static void callTraceFunction(Ruby runtime, ThreadContext context, RubyEvent event) {
        String name = context.getFrameName();
        RubyModule type = context.getFrameKlazz();
        runtime.callEventHooks(context, event, context.getFile(), context.getLine(), name, type);
    }

    protected void op_plus(Ruby runtime, ThreadContext context, InlineCache ic, IRubyObject self,
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
            sendVirtual1Arg(runtime, context, ic, self, "+", receiver, other);
            // push(receiver.callMethod(context, "+", other));
        }
    }

    protected void op_minus(Ruby runtime, ThreadContext context, InlineCache ic, IRubyObject self,
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
            sendVirtual1Arg(runtime, context, ic, self, "-", receiver, other);
            // push(receiver.callMethod(context, "-", other));
        }
    }

    protected void op_lt(Ruby runtime, ThreadContext context, InlineCache ic, IRubyObject self,
            IRubyObject other, IRubyObject receiver) {
        if (other instanceof RubyFixnum && receiver instanceof RubyFixnum) {
            long receiverValue = ((RubyFixnum) receiver).getLongValue();
            long otherValue = ((RubyFixnum) other).getLongValue();

            push(runtime.newBoolean(receiverValue < otherValue));
        } else {
            sendVirtual1Arg(runtime, context, ic, self, "<", receiver, other);
            // push(receiver.callMethod(context, "<", other));
        }
    }

    protected void op_gt(Ruby runtime, ThreadContext context, InlineCache ic, IRubyObject self,
            IRubyObject other, IRubyObject receiver) {
        if (other instanceof RubyFixnum && receiver instanceof RubyFixnum) {
            long receiverValue = ((RubyFixnum) receiver).getLongValue();
            long otherValue = ((RubyFixnum) other).getLongValue();

            push(runtime.newBoolean(receiverValue > otherValue));
        } else {
            sendVirtual1Arg(runtime, context, ic, self, ">", receiver, other);
            // push(receiver.callMethod(context, ">", other));
        }
    }

    protected int send(Ruby runtime, ThreadContext context, IRubyObject self, String name, int size,
            YARVByteCode blockByteCode, int flags, InlineCache ic, byte[] body, int stackStart,
            int nextInstructionPos) {
        Block block = null;

        if (blockByteCode != null) {
            YARVBlockBody blockBody = getBlockBody(blockByteCode, runtime, context);

            blockBody.getStaticScope().determineModule();
            Binding binding = context.currentBinding(self, Visibility.PUBLIC);

            block = new Block(blockBody, binding);
        } else if ((flags & YARVInstructions.ARGS_BLOCKARG_FLAG) != 0) {
            System.err.println("block arg support not implemented");
        }

        if (ic.cachedObject == null) {
            if ((flags & YARVInstructions.VCALL_FLAG) == 0) {
                if ((flags & YARVInstructions.FCALL_FLAG) == 0) {
                    ic.cachedObject = MethodIndex.getCallSite(name);
                } else {
                    ic.cachedObject = MethodIndex.getFunctionalCallSite(name);
                }
            } else {
                ic.cachedObject = MethodIndex.getVariableCallSite(name);
            }
        }
        CallSite callAdapter = (CallSite) ic.cachedObject;

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
            if (TAILCALL_OPT && isTailCall(context, body, flags, recv, self, flags, name)) {
                stackTop = stackStart;
                nextInstructionPos = -1;

                IRubyObject[] vals = context.getCurrentScope().getValues();
                vals[0] = arg1;
                vals[1] = arg2;
                vals[2] = arg3;
            } else {
                if (block == null) {
                    push(callAdapter.call(context, self, recv, arg1, arg2, arg3));
                } else {
                    push(callAdapter.call(context, self, recv, arg1, arg2, arg3, block));
                }
            }
            break;
        }
        case 2: {
            IRubyObject arg2 = pop();
            IRubyObject arg1 = pop();

            IRubyObject recv = pop();
            if (TAILCALL_OPT && isTailCall(context, body, flags, recv, self, flags, name)) {
                stackTop = stackStart;
                nextInstructionPos = -1;

                IRubyObject[] vals = context.getCurrentScope().getValues();
                vals[0] = arg1;
                vals[1] = arg2;
            } else {
                if (block == null) {
                    push(callAdapter.call(context, self, recv, arg1, arg2));
                } else {
                    push(callAdapter.call(context, self, recv, arg1, arg2, block));
                }
            }
            break;
        }
        case 1: {
            IRubyObject arg1 = pop();

            IRubyObject recv = pop();
            if (TAILCALL_OPT && isTailCall(context, body, flags, recv, self, flags, name)) {
                stackTop = stackStart;
                nextInstructionPos = -1;

                IRubyObject[] vals = context.getCurrentScope().getValues();
                vals[0] = arg1;
            } else {
                if (block == null) {
                    push(callAdapter.call(context, self, recv, arg1));
                } else {
                    push(callAdapter.call(context, self, recv, arg1, block));
                }
            }
            break;
        }
        case 0: {
            IRubyObject recv = pop();
            if (TAILCALL_OPT && isTailCall(context, body, flags, recv, self, flags, name)) {
                stackTop = stackStart;
                nextInstructionPos = -1;
            } else {
                if (block == null) {
                    push(callAdapter.call(context, self, recv));
                } else {
                    push(callAdapter.call(context, self, recv, block));
                }
            }
            break;
        }
        default: {
            IRubyObject[] args;
            args = new IRubyObject[size];
            popArray(args);

            IRubyObject recv = pop();
            if (TAILCALL_OPT && isTailCall(context, body, flags, recv, self, flags, name)) {
                stackTop = stackStart;
                nextInstructionPos = -1;

                IRubyObject[] vals = context.getCurrentScope().getValues();
                for (int i = 0; i < size; i++) {
                    vals[i] = args[i];
                }
            } else {
                if (block == null) {
                    push(callAdapter.call(context, self, recv, args));
                } else {
                    push(callAdapter.call(context, self, recv, args, block));
                }
            }
            break;
        }
        }

        return nextInstructionPos;
    }

    private YARVBlockBody getBlockBody(YARVByteCode blockByteCode, Ruby runtime, ThreadContext context) {
        YARVBlockBody blockBody = blockByteCode.blockBody;

        if (blockBody == null) {
            // TODO argumentType array (for lambdas?)
            boolean opts = blockByteCode.getOptArgsLength() > 0 || blockByteCode.args_rest > 0;
            boolean req = blockByteCode.args_argc > 0;
            Arity arity;
            int argumentType = BlockBody.MULTIPLE_ASSIGNMENT;
            if (!req && !opts) {
                arity = Arity.noArguments();
                argumentType = BlockBody.ZERO_ARGS;
            } else if (req && !opts) {
                arity = Arity.fixed(blockByteCode.args_argc);
            } else if (opts && !req) {
                arity = Arity.optional();
                if (blockByteCode.args_rest > 0 && blockByteCode.getOptArgsLength() <= 0) {
                    argumentType = BlockBody.SINGLE_RESTARG;
                }
            } else {
                arity = Arity.required(blockByteCode.args_argc);
            }

            StaticScope scope = runtime.getStaticScopeFactory().newBlockScope(
                    context.getCurrentStaticScope());
            scope.setVariables(blockByteCode.locals);
            // TODO when evaluating method call, iteration has to
            // proceed and set argument variables accordingly.
            blockBody = new YARVBlockBody(scope, arity, argumentType, blockByteCode);
            blockByteCode.blockBody = blockBody;
        }
        
        return blockBody;
    }

    protected boolean isTailCall(ThreadContext context, byte[] body, int nextInstructionPos,
            IRubyObject recv, IRubyObject self, int flags, String name) {
        return (body[nextInstructionPos] == YARVInstructions.LEAVE || (flags & YARVInstructions.TAILCALL_FLAG) == YARVInstructions.TAILCALL_FLAG)
                && recv == self && name.equals(context.getFrameName());
    }

    protected void sendVirtual(Ruby runtime, ThreadContext context, InlineCache ic, IRubyObject self,
            String name, int size) {
        if (size == 3) {
            sendVirtual3Args(runtime, context, ic, self, name);
        } else if (size == 2) {
            sendVirtual2Args(runtime, context, ic, self, name);
        } else if (size == 1) {
            sendVirtual1Arg(runtime, context, ic, self, name);
        } else if (size == 0) {
            sendVirtual0Args(runtime, context, ic, self, name);
        } else {
            sendVirtualManyArgs(runtime, context, ic, self, name, size);
        }
    }

    protected void sendVirtual0Args(Ruby runtime, ThreadContext context, InlineCache ic,
            IRubyObject self, String name) {
        if (ic.cachedObject == null) {
            ic.cachedObject = MethodIndex.getCallSite(name);
        }

        push(((CallSite) ic.cachedObject).call(context, self, pop()));
    }

    protected void sendVirtual1Arg(Ruby runtime, ThreadContext context, InlineCache ic,
            IRubyObject self, String name) {
        if (ic.cachedObject == null) {
            ic.cachedObject = MethodIndex.getCallSite(name);
        }

        IRubyObject arg1 = pop();
        push(((CallSite) ic.cachedObject).call(context, self, pop(), arg1));
    }

    protected void sendVirtual1Arg(Ruby runtime, ThreadContext context, InlineCache ic,
            IRubyObject self, String name, IRubyObject recv, IRubyObject arg1) {
        if (ic.cachedObject == null) {
            ic.cachedObject = MethodIndex.getCallSite(name);
        }

        push(((CallSite) ic.cachedObject).call(context, self, recv, arg1));
    }

    protected void sendVirtual2Args(Ruby runtime, ThreadContext context, InlineCache ic,
            IRubyObject self, String name) {
        if (ic.cachedObject == null) {
            ic.cachedObject = MethodIndex.getCallSite(name);
        }

        IRubyObject arg2 = pop();
        IRubyObject arg1 = pop();
        push(((CallSite) ic.cachedObject).call(context, self, pop(), arg1, arg2));
    }

    protected void sendVirtual2Args(Ruby runtime, ThreadContext context, InlineCache ic,
            IRubyObject self, String name, IRubyObject recv, IRubyObject arg1, IRubyObject arg2) {
        if (ic.cachedObject == null) {
            ic.cachedObject = MethodIndex.getCallSite(name);
        }

        push(((CallSite) ic.cachedObject).call(context, self, recv, arg1, arg2));
    }

    protected void sendVirtual3Args(Ruby runtime, ThreadContext context, InlineCache ic,
            IRubyObject self, String name) {
        if (ic.cachedObject == null) {
            ic.cachedObject = MethodIndex.getCallSite(name);
        }

        IRubyObject arg3 = pop();
        IRubyObject arg2 = pop();
        IRubyObject arg1 = pop();
        push(((CallSite) ic.cachedObject).call(context, self, pop(), arg1, arg2, arg3));
    }

    protected void sendVirtual3Args(Ruby runtime, ThreadContext context, InlineCache ic,
            IRubyObject self, String name, IRubyObject recv, IRubyObject arg1, IRubyObject arg2,
            IRubyObject arg3) {
        if (ic.cachedObject == null) {
            ic.cachedObject = MethodIndex.getCallSite(name);
        }

        push(((CallSite) ic.cachedObject).call(context, self, recv, arg1, arg2, arg3));
    }

    protected void sendVirtualManyArgs(Ruby runtime, ThreadContext context, InlineCache ic,
            IRubyObject self, String name, int size) {
        if (ic.cachedObject == null) {
            ic.cachedObject = MethodIndex.getCallSite(name);
        }

        IRubyObject[] args;
        if (size == 0) {
            args = IRubyObject.NULL_ARRAY;
        } else {
            args = new IRubyObject[size];
            popArray(args);
        }
        push(((CallSite) ic.cachedObject).call(context, self, pop(), args));
    }

    // TODO caching call sites do not make sense if not stored. (store with
// instruction)?
    // TODO do we need to intern() method names?
}
