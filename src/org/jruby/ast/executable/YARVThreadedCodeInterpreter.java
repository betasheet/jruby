/*
 * **** BEGIN LICENSE BLOCK ***** Version: CPL 1.0/GPL 2.0/LGPL 2.1 The contents
 * of this file are subject to the Common Public License Version 1.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.eclipse.org/legal/cpl-v10.html Software distributed under the
 * License is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND,
 * either express or implied. See the License for the specific language
 * governing rights and limitations under the License. Alternatively, the
 * contents of this file may be used under the terms of either of the GNU
 * General Public License Version 2 or later (the "GPL"), or the GNU Lesser
 * General Public License Version 2.1 or later (the "LGPL"), in which case the
 * provisions of the GPL or the LGPL are applicable instead of those above. If
 * you wish to allow use of your version of this file only under the terms of
 * either the GPL or the LGPL, and not to allow others to use your version of
 * this file under the terms of the CPL, indicate your decision by deleting the
 * provisions above and replace them with the notice and other provisions
 * required by the GPL or the LGPL. If you do not delete the provisions above, a
 * recipient may use your version of this file under the terms of any one of the
 * CPL, the GPL or the LGPL.**** END LICENSE BLOCK ****
 */
package org.jruby.ast.executable;

import static com.sun.max.vm.compiler.CallEntryPoint.OPTIMIZED_ENTRY_POINT;

import org.jruby.MetaClass;
import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyBignum;
import org.jruby.RubyClass;
import org.jruby.RubyFixnum;
import org.jruby.RubyFloat;
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

import com.sun.max.vm.Intrinsics;

/**
 * @author betasheet
 */
public class YARVThreadedCodeInterpreter extends YARVMachine {

    @Override
    public IRubyObject exec(ThreadContext context, StaticScope scope, YARVByteCode byteCode) {
        try {
            context.preScopedBody(new ManyVarsDynamicScope(scope));

            if (scope.getModule() == null) {
                scope.setModule(context.getRuntime().getObject());
            }

            return exec(context, context.getRuntime().getObject(), byteCode);
        } finally {
            context.postScopedBody();
        }
    }

    @Override
    public IRubyObject exec(ThreadContext context, IRubyObject self, YARVByteCode byteCode) {
        return new ActivationRecord(context, self, byteCode).execute();
    }

    public class ActivationRecord {
        private final ThreadContext context;
        private final Ruby runtime;
        private final IRubyObject self;
        private final YARVByteCode byteCode;

        public ActivationRecord(ThreadContext context, IRubyObject self, YARVByteCode byteCode) {
            this.context = context;
            this.runtime = context.runtime;
            this.self = self;
            this.byteCode = byteCode;
        }

        ActivationRecord() {
            context = null;
            runtime = null;
            self = null;
            byteCode = null;
        }

        public IRubyObject execute() {
            Intrinsics.indirectCallWithReceiver(
                    byteCode.targetMethod.getEntryPoint(OPTIMIZED_ENTRY_POINT).toAddress(), this);
            return pop();
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.NOP)
        public void nopTemplate() {
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.GETGLOBAL)
        public void getGlobalTemplate(int op0) {
            String op = (String) YARVByteCode.getConstant(op0);
            push(runtime.getGlobalVariables().get(op));
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.SETGLOBAL)
        public void setGlobalTemplate(int op0) {
            String op = (String) YARVByteCode.getConstant(op0);
            runtime.getGlobalVariables().set(op, pop());
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.GETLOCAL)
        public void getLocalTemplate(int idx) {
            DynamicScope scope = context.getCurrentScope().localScope;
            idx = scope.getStaticScope().getNumberOfVariables() - idx;
            push(scope.getValue(idx, 0));
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.SETLOCAL)
        public void setLocalTemplate(int idx) {
            DynamicScope scope = context.getCurrentScope().localScope;
            idx = scope.getStaticScope().getNumberOfVariables() - idx;
            scope.setValue(idx, pop(), 0);
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.GETDYNAMIC)
        public void getDynamicTemplate(int idx, int depth) {
            DynamicScope scope = context.getCurrentScope();
            if (depth > 0) {
                scope = scope.getNthParentScope(depth);
            }
            idx = scope.getStaticScope().getNumberOfVariables() - idx;
            push(scope.getValue(idx, 0));
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.SETDYNAMIC)
        public void setDynamicTemplate(int idx, int depth) {
            DynamicScope scope = context.getCurrentScope();
            if (depth > 0) {
                scope = scope.getNthParentScope(depth);
            }
            idx = scope.getStaticScope().getNumberOfVariables() - idx;
            scope.setValue(idx, pop(), 0);
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.GETINSTANCEVARIABLE)
        public void getInstanceVariableTemplate(int op0) {
            String op = (String) YARVByteCode.getConstant(op0);
            push(self.getInstanceVariables().getInstanceVariable(op));
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.SETINSTANCEVARIABLE)
        public void setInstanceVariableTemplate(int op0) {
            String op = (String) YARVByteCode.getConstant(op0);
            self.getInstanceVariables().setInstanceVariable(op, pop());
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.GETCLASSVARIABLE)
        public void getClassVariableTemplate(int op0) {
            RubyModule rubyClass = context.getRubyClass();
            String name = (String) YARVByteCode.getConstant(op0);

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
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.SETCLASSVARIABLE)
        public void setClassVariableTemplate(int op0) {
            RubyModule rubyClass = context.getCurrentScope().getStaticScope().getModule();
            String name = (String) YARVByteCode.getConstant(op0);

            if (rubyClass == null) {
                rubyClass = self.getMetaClass();
            } else if (rubyClass.isSingleton()) {
                rubyClass = (RubyModule) (((MetaClass) rubyClass).getAttached());
            }

            rubyClass.setClassVar(name, pop());
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.GETCONSTANT)
        public void getConstantTemplate(int op0) {
            String op = (String) YARVByteCode.getConstant(op0);
            IRubyObject klass = pop();
            if (klass == null || klass == runtime.getNil()) {
                push(context.getCurrentStaticScope().getConstant(op));
            } else {
                push(((RubyModule) klass).getConstant(op));
            }
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.SETCONSTANT)
        public void setConstantTemplate(int op0) {
            String op = (String) YARVByteCode.getConstant(op0);
            IRubyObject klass = pop();
            IRubyObject value = pop();
            if (klass == null || klass == runtime.getNil()) {
                context.getCurrentStaticScope().setConstant(op, value);
                runtime.incGlobalState();
            } else {
                push(((RubyModule) klass).setConstant(op, value));
                runtime.incGlobalState();
            }
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.PUTNIL)
        public void putNilTemplate() {
            push(runtime.getNil());
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.PUTSELF)
        public void putSelfTemplate() {
            push(self);
        }

        @YARVBYTECODEIMPLEMENTATION({ YARVInstructions.PUTOBJECT, YARVInstructions.PUTISEQ })
        public void putObjectTemplate(int op0) {
            IRubyObject op = (IRubyObject) YARVByteCode.getConstant(op0);
            push(op);
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.PUTSPECIALOBJECT)
        public void putSpecialObjectTemplate(int op) {
            // TODO cbase / const base difference (put by eval?
// vm_insnhelper.c)
            if (op == 1) { // VM_SPECIAL_OBJECT_VMCORE
                push(runtime.getYarvVMCore());
            } else if (op == 2) { // VM_SPECIAL_OBJECT_CBASE
                push(context.getRubyClass());
            } else if (op == 3) { // VM_SPECIAL_OBJECT_CONST_BASE
                push(context.getRubyClass());
            } else {
                unimplemented(YARVInstructions.PUTSPECIALOBJECT);
            }
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.DEFINECLASS)
        public void defineClassTemplate(int op0, int op1, int type) {
            IRubyObject parentClass = pop();
            IRubyObject cBase = pop();
            String name = (String) YARVByteCode.getConstant(op0);
            YARVByteCode bc = (YARVByteCode) YARVByteCode.getConstant(op1);

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
                    newClass = ((RubyClass) cBase).defineClassUnder(name, (RubyClass) parentClass,
                            ((RubyClass) parentClass).getAllocator());
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
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.PUTSTRING)
        public void putStringTemplate(int op0) {
            String op = (String) YARVByteCode.getConstant(op0);
            push(runtime.newString(op));
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.CONCATSTRINGS)
        public void concatStringsTemplate(int op) {
            StringBuilder concatter = new StringBuilder();

            for (int i = (int) (stackTop - op); i < stackTop; i++) {
                concatter.append(stack[i].toString());
            }
            stackTop -= op;

            push(runtime.newString(concatter.toString()));
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.TOSTRING)
        public void toStringTemplate() {
            IRubyObject top = peek();
            if (!(top instanceof RubyString)) {
                set(top.callMethod(context, "to_s"));
            }
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.TOREGEXP)
        public void toRegExpTemplate(int options, int count) {
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
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.NEWARRAY)
        public void newArrayTemplate(int op) {
            push(runtime.newArrayNoCopy(popArray(new IRubyObject[op])));
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.DUPARRAY)
        public void dupArrayTemplate(int op0) {
            IRubyObject op = (IRubyObject) YARVByteCode.getConstant(op0);
            push(op.dup());
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.EXPANDARRAY)
        public void expandArrayTemplate(int op, int flag) {
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
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.NEWHASH)
        public void newHashTemplate(int hsize) {
            RubyHash h = RubyHash.newHash(runtime);
            IRubyObject v, k;
            for (int i = hsize; i > 0; i -= 2) {
                v = pop();
                k = pop();
                h.op_aset(context, k, v);
            }
            push(h);
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.NEWRANGE)
        public void newRangeTemplate(int op) {
            // high, low, flag
            IRubyObject end = pop();
            IRubyObject begin = pop();
            push(RubyRange.newRange(runtime, context, begin, end, op != 0));
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.POP)
        public void popTemplate() {
            pop();
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.DUP)
        public void dupTemplate() {
            push(peek());
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.DUPN)
        public void dupnTemplate(int op) {
            dupn(op);
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.SWAP)
        public void swapTemplate() {
            swap();
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.TOPN)
        public void topnTemplate(int op) {
            topn(op);
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.SETN)
        public void setnTemplate(int op) {
            setn(op, peek());
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.SEND_MANY_ARG)
        public void sendManyArgTemplate(int op0, int size, int flags, int icId) {
            String name = (String) YARVByteCode.getConstant(op0);

            InlineCache ic = byteCode.getInlineCache(icId);
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

            IRubyObject[] args;
            args = new IRubyObject[size];
            popArray(args);

            IRubyObject recv = pop();
            push(callAdapter.call(context, self, recv, args));
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.SEND_MANY_ARG_BLOCK)
        public void sendManyArgBlockTemplate(int op0, int size, int op2, int flags, int icId) {
            String name = (String) YARVByteCode.getConstant(op0);

            YARVByteCode blockByteCode = (YARVByteCode) YARVByteCode.getConstant(op2);
            YARVBlockBody blockBody = getBlockBody(blockByteCode);
            blockBody.getStaticScope().determineModule();
            Binding binding = context.currentBinding(self, Visibility.PUBLIC);
            Block block = new Block(blockBody, binding);

            InlineCache ic = byteCode.getInlineCache(icId);
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

            IRubyObject[] args;
            args = new IRubyObject[size];
            popArray(args);

            IRubyObject recv = pop();
            push(callAdapter.call(context, self, recv, args, block));
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.SEND_NO_ARG)
        public void sendNoArgTemplate(int op0, int flags, int icId) {
            String name = (String) YARVByteCode.getConstant(op0);

            InlineCache ic = byteCode.getInlineCache(icId);

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

            IRubyObject recv = pop();
            push(callAdapter.call(context, self, recv));
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.SEND_NO_ARG_BLOCK)
        public void sendNoArgBlockTemplate(int op0, int op2, int flags, int icId) {
            String name = (String) YARVByteCode.getConstant(op0);

            YARVByteCode blockByteCode = (YARVByteCode) YARVByteCode.getConstant(op2);
            YARVBlockBody blockBody = getBlockBody(blockByteCode);
            blockBody.getStaticScope().determineModule();
            Binding binding = context.currentBinding(self, Visibility.PUBLIC);
            Block block = new Block(blockBody, binding);

            InlineCache ic = byteCode.getInlineCache(icId);
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

            IRubyObject recv = pop();
            push(callAdapter.call(context, self, recv, block));
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.SEND_ONE_ARG)
        public void sendOneArgTemplate(int op0, int flags, int icId) {
            String name = (String) YARVByteCode.getConstant(op0);

            InlineCache ic = byteCode.getInlineCache(icId);

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

            IRubyObject arg1 = pop();
            IRubyObject recv = pop();
            push(callAdapter.call(context, self, recv, arg1));
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.SEND_ONE_ARG_BLOCK)
        public void sendOneArgBlockTemplate(int op0, int op2, int flags, int icId) {
            String name = (String) YARVByteCode.getConstant(op0);

            YARVByteCode blockByteCode = (YARVByteCode) YARVByteCode.getConstant(op2);
            YARVBlockBody blockBody = getBlockBody(blockByteCode);
            blockBody.getStaticScope().determineModule();
            Binding binding = context.currentBinding(self, Visibility.PUBLIC);
            Block block = new Block(blockBody, binding);

            InlineCache ic = byteCode.getInlineCache(icId);
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

            IRubyObject arg1 = pop();
            IRubyObject recv = pop();
            push(callAdapter.call(context, self, recv, arg1, block));
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.SEND_TWO_ARG)
        public void sendTwoArgTemplate(int op0, int flags, int icId) {
            String name = (String) YARVByteCode.getConstant(op0);

            InlineCache ic = byteCode.getInlineCache(icId);

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

            IRubyObject arg2 = pop();
            IRubyObject arg1 = pop();
            IRubyObject recv = pop();
            push(callAdapter.call(context, self, recv, arg1, arg2));
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.SEND_TWO_ARG_BLOCK)
        public void sendTwoArgBlockTemplate(int op0, int op2, int flags, int icId) {
            String name = (String) YARVByteCode.getConstant(op0);

            YARVByteCode blockByteCode = (YARVByteCode) YARVByteCode.getConstant(op2);
            YARVBlockBody blockBody = getBlockBody(blockByteCode);
            blockBody.getStaticScope().determineModule();
            Binding binding = context.currentBinding(self, Visibility.PUBLIC);
            Block block = new Block(blockBody, binding);

            InlineCache ic = byteCode.getInlineCache(icId);
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

            IRubyObject arg2 = pop();
            IRubyObject arg1 = pop();
            IRubyObject recv = pop();
            push(callAdapter.call(context, self, recv, arg1, arg2, block));
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.SEND_THREE_ARG)
        public void sendThreeArgTemplate(int op0, int flags, int icId) {
            String name = (String) YARVByteCode.getConstant(op0);

            InlineCache ic = byteCode.getInlineCache(icId);

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

            IRubyObject arg3 = pop();
            IRubyObject arg2 = pop();
            IRubyObject arg1 = pop();
            IRubyObject recv = pop();
            push(callAdapter.call(context, self, recv, arg1, arg2, arg3));
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.SEND_THREE_ARG_BLOCK)
        public void sendThreeArgBlockTemplate(int op0, int op2, int flags, int icId) {
            String name = (String) YARVByteCode.getConstant(op0);

            YARVByteCode blockByteCode = (YARVByteCode) YARVByteCode.getConstant(op2);
            YARVBlockBody blockBody = getBlockBody(blockByteCode);
            blockBody.getStaticScope().determineModule();
            Binding binding = context.currentBinding(self, Visibility.PUBLIC);
            Block block = new Block(blockBody, binding);

            InlineCache ic = byteCode.getInlineCache(icId);
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

            IRubyObject arg3 = pop();
            IRubyObject arg2 = pop();
            IRubyObject arg1 = pop();
            IRubyObject recv = pop();
            push(callAdapter.call(context, self, recv, arg1, arg2, arg3, block));
        }

        private YARVBlockBody getBlockBody(YARVByteCode blockByteCode) {
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

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.LEAVE)
        public void leaveTemplate() {
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.JUMP)
        public void jumpTemplate() {
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.BRANCHIF)
        public boolean branchIfTemplate() {
            return pop().isTrue();
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.BRANCHUNLESS)
        public boolean branchUnlessTemplate() {
            return !pop().isTrue();
        }

        @YARVBYTECODEIMPLEMENTATION({ YARVInstructions.GETINLINECACHE,
                YARVInstructions.ONCEINLINECACHE })
        public boolean getInlineCacheTemplate(int icId) {
            InlineCache ic = byteCode.getInlineCache(icId);
            Object cachedObject;
            if ((cachedObject = ic.get(runtime.getGlobalState())) != null) {
                push((IRubyObject) cachedObject);
                return true;
            }
            push(runtime.getNil());
            return false;
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.SETINLINECACHE)
        public void setInlineCacheTemplate(int icId) {
            InlineCache ic = byteCode.getInlineCache(icId);
            ic.update(runtime.getGlobalState(), peek());
        }

        // TODO OPT implementations should check for redefinition of methods

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.OPT_PLUS)
        public void optPlusTemplate(int op) {
            IRubyObject other = pop();
            IRubyObject receiver = pop();
            if (other instanceof RubyFixnum && receiver instanceof RubyFixnum) {
                long receiverValue = ((RubyFixnum) receiver).getLongValue();
                long otherValue = ((RubyFixnum) other).getLongValue();
                long result = receiverValue + otherValue;
                if ((~(receiverValue ^ otherValue) & (receiverValue ^ result) & RubyFixnum.SIGN_BIT) != 0) {
                    push(RubyBignum.newBignum(runtime, receiverValue).op_plus(context, other));
                } else {
                    push(runtime.newFixnum(result));
                }
            } else if (other instanceof RubyFloat && receiver instanceof RubyFloat) {
                double receiverValue = ((RubyFloat) receiver).getDoubleValue();
                double otherValue = ((RubyFloat) other).getDoubleValue();
                double result = receiverValue + otherValue;
                push(runtime.newFloat(result));
            } else if (other instanceof RubyString && receiver instanceof RubyString) {
                String receiverValue = ((RubyString) receiver).toString();
                String otherValue = ((RubyString) other).toString();
                String result = receiverValue + otherValue;
                push(runtime.newString(result));
            } else if (receiver instanceof RubyArray) {
                push(((RubyArray) receiver).op_plus(other));
            } else {
                InlineCache ic = byteCode.getInlineCache(op);
                sendVirtual1Arg(runtime, context, ic, self, "+", receiver, other);
            }
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.OPT_MINUS)
        public void optMinusTemplate(int op) {
            IRubyObject other = pop();
            IRubyObject receiver = pop();
            if (other instanceof RubyFixnum && receiver instanceof RubyFixnum) {
                long receiverValue = ((RubyFixnum) receiver).getLongValue();
                long otherValue = ((RubyFixnum) other).getLongValue();
                long result = receiverValue - otherValue;
                if ((~(receiverValue ^ otherValue) & (receiverValue ^ result) & RubyFixnum.SIGN_BIT) != 0) {
                    push(RubyBignum.newBignum(runtime, receiverValue).op_minus(context, other));
                } else {
                    push(runtime.newFixnum(result));
                }
            } else if (other instanceof RubyFloat && receiver instanceof RubyFloat) {
                double receiverValue = ((RubyFloat) receiver).getDoubleValue();
                double otherValue = ((RubyFloat) other).getDoubleValue();
                double result = receiverValue - otherValue;
                push(runtime.newFloat(result));
            } else {
                InlineCache ic = byteCode.getInlineCache(op);
                sendVirtual1Arg(runtime, context, ic, self, "-", receiver, other);
            }
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.OPT_MULT)
        public void optMultTemplate(int op) {
            IRubyObject other = pop();
            IRubyObject receiver = pop();
            if (other instanceof RubyFixnum && receiver instanceof RubyFixnum) {
                long receiverValue = ((RubyFixnum) receiver).getLongValue();
                if (receiverValue == 0) {
                    push(runtime.newFixnum(0));
                } else {
                    long otherValue = ((RubyFixnum) other).getLongValue();
                    long result = receiverValue * otherValue;
                    if (result / receiverValue != otherValue) {
                        push(RubyBignum.newBignum(runtime, receiverValue).op_mul(context, other));
                    } else {
                        push(runtime.newFixnum(result));
                    }
                }
            } else if (other instanceof RubyFloat && receiver instanceof RubyFloat) {
                double receiverValue = ((RubyFloat) receiver).getDoubleValue();
                double otherValue = ((RubyFloat) other).getDoubleValue();
                double result = receiverValue * otherValue;
                push(runtime.newFloat(result));
            } else {
                InlineCache ic = byteCode.getInlineCache(op);
                sendVirtual1Arg(runtime, context, ic, self, "*", receiver, other);
            }
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.OPT_DIV)
        public void optDivTemplate(int op) {
            IRubyObject other = pop();
            IRubyObject receiver = pop();
            if (other instanceof RubyFixnum && receiver instanceof RubyFixnum) {
                long receiverValue = ((RubyFixnum) receiver).getLongValue();
                long otherValue = ((RubyFixnum) other).getLongValue();
                if (otherValue == 0) {
                    InlineCache ic = byteCode.getInlineCache(op);
                    sendVirtual1Arg(runtime, context, ic, self, "/", receiver, other);
                }

                long result;
                if (otherValue < 0) {
                    if (receiverValue < 0)
                        result = -receiverValue / -otherValue;
                    else
                        result = -(receiverValue / -otherValue);
                } else {
                    if (receiverValue < 0)
                        result = -(-receiverValue / otherValue);
                    else
                        result = receiverValue / otherValue;
                }
                long mod = receiverValue - result * otherValue;
                if ((mod < 0 && otherValue > 0) || (mod > 0 && otherValue < 0)) {
                    mod += otherValue;
                    result -= 1;
                }

                push(runtime.newFixnum(result));
            } else if (other instanceof RubyFloat && receiver instanceof RubyFloat) {
                double receiverValue = ((RubyFloat) receiver).getDoubleValue();
                double otherValue = ((RubyFloat) other).getDoubleValue();
                double result = receiverValue / otherValue;
                push(runtime.newFloat(result));
            } else {
                InlineCache ic = byteCode.getInlineCache(op);
                sendVirtual1Arg(runtime, context, ic, self, "/", receiver, other);
            }
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.OPT_MOD)
        public void optModTemplate(int op) {
            IRubyObject other = pop();
            IRubyObject receiver = pop();
            if (other instanceof RubyFixnum && receiver instanceof RubyFixnum) {
                long receiverValue = ((RubyFixnum) receiver).getLongValue();
                long otherValue = ((RubyFixnum) other).getLongValue();
                if (otherValue == 0) {
                    InlineCache ic = byteCode.getInlineCache(op);
                    sendVirtual1Arg(runtime, context, ic, self, "%", receiver, other);
                }

                long result;
                if (otherValue < 0) {
                    if (receiverValue < 0)
                        result = -receiverValue / -otherValue;
                    else
                        result = -(receiverValue / -otherValue);
                } else {
                    if (receiverValue < 0)
                        result = -(-receiverValue / otherValue);
                    else
                        result = receiverValue / otherValue;
                }
                long mod = receiverValue - result * otherValue;
                if ((mod < 0 && otherValue > 0) || (mod > 0 && otherValue < 0)) {
                    mod += otherValue;
                    result -= 1;
                }

                push(runtime.newFixnum(mod));
            } else if (other instanceof RubyFloat && receiver instanceof RubyFloat) {
                double receiverValue = ((RubyFloat) receiver).getDoubleValue();
                double otherValue = ((RubyFloat) other).getDoubleValue();
                double result = receiverValue % otherValue;
                push(runtime.newFloat(result));
            } else {
                InlineCache ic = byteCode.getInlineCache(op);
                sendVirtual1Arg(runtime, context, ic, self, "%", receiver, other);
            }
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.OPT_EQ)
        public void optEqTemplate(int op) {
            IRubyObject other = pop();
            IRubyObject receiver = pop();
            if (other instanceof RubyFixnum && receiver instanceof RubyFixnum) {
                long receiverValue = ((RubyFixnum) receiver).getLongValue();
                long otherValue = ((RubyFixnum) other).getLongValue();

                push(runtime.newBoolean(receiverValue == otherValue));
            } else if (other instanceof RubyFloat && receiver instanceof RubyFloat) {
                double receiverValue = ((RubyFloat) receiver).getDoubleValue();
                double otherValue = ((RubyFloat) other).getDoubleValue();

                push(runtime.newBoolean(receiverValue == otherValue));
            } else {
                InlineCache ic = byteCode.getInlineCache(op);
                sendVirtual1Arg(runtime, context, ic, self, "==", receiver, other);
            }
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.OPT_NEQ)
        public void optNeqTemplate(int op) {
            IRubyObject other = pop();
            IRubyObject receiver = pop();
            if (other instanceof RubyFixnum && receiver instanceof RubyFixnum) {
                long receiverValue = ((RubyFixnum) receiver).getLongValue();
                long otherValue = ((RubyFixnum) other).getLongValue();

                push(runtime.newBoolean(receiverValue != otherValue));
            } else if (other instanceof RubyFloat && receiver instanceof RubyFloat) {
                double receiverValue = ((RubyFloat) receiver).getDoubleValue();
                double otherValue = ((RubyFloat) other).getDoubleValue();

                push(runtime.newBoolean(receiverValue != otherValue));
            } else {
                InlineCache ic = byteCode.getInlineCache(op);
                sendVirtual1Arg(runtime, context, ic, self, "!=", receiver, other);
            }
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.OPT_LT)
        public void optLtTemplate(int op) {
            IRubyObject other = pop();
            IRubyObject receiver = pop();
            if (other instanceof RubyFixnum && receiver instanceof RubyFixnum) {
                long receiverValue = ((RubyFixnum) receiver).getLongValue();
                long otherValue = ((RubyFixnum) other).getLongValue();

                push(runtime.newBoolean(receiverValue < otherValue));
            } else if (other instanceof RubyFloat && receiver instanceof RubyFloat) {
                double receiverValue = ((RubyFloat) receiver).getDoubleValue();
                double otherValue = ((RubyFloat) other).getDoubleValue();

                push(runtime.newBoolean(receiverValue < otherValue));
            } else {
                InlineCache ic = byteCode.getInlineCache(op);
                sendVirtual1Arg(runtime, context, ic, self, "<", receiver, other);
            }
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.OPT_LE)
        public void optLeTemplate(int op) {
            IRubyObject other = pop();
            IRubyObject receiver = pop();
            if (other instanceof RubyFixnum && receiver instanceof RubyFixnum) {
                long receiverValue = ((RubyFixnum) receiver).getLongValue();
                long otherValue = ((RubyFixnum) other).getLongValue();

                push(runtime.newBoolean(receiverValue <= otherValue));
            } else if (other instanceof RubyFloat && receiver instanceof RubyFloat) {
                double receiverValue = ((RubyFloat) receiver).getDoubleValue();
                double otherValue = ((RubyFloat) other).getDoubleValue();

                push(runtime.newBoolean(receiverValue <= otherValue));
            } else {
                InlineCache ic = byteCode.getInlineCache(op);
                sendVirtual1Arg(runtime, context, ic, self, "<=", receiver, other);
            }
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.OPT_LTLT)
        public void optLtLtTemplate(int op) {
            IRubyObject other = pop();
            IRubyObject receiver = pop();
            if (other instanceof RubyString && receiver instanceof RubyString) {
                String receiverValue = ((RubyString) receiver).toString();
                String otherValue = ((RubyString) other).toString();
                String result = receiverValue + otherValue;
                push(runtime.newString(result));
            } else if (receiver instanceof RubyArray) {
                push(((RubyArray) receiver).append(other));
            } else {
                InlineCache ic = byteCode.getInlineCache(op);
                sendVirtual1Arg(runtime, context, ic, self, "<<", receiver, other);
            }
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.OPT_GT)
        public void optGtTemplate(int op) {
            IRubyObject other = pop();
            IRubyObject receiver = pop();
            if (other instanceof RubyFixnum && receiver instanceof RubyFixnum) {
                long receiverValue = ((RubyFixnum) receiver).getLongValue();
                long otherValue = ((RubyFixnum) other).getLongValue();

                push(runtime.newBoolean(receiverValue > otherValue));
            } else if (other instanceof RubyFloat && receiver instanceof RubyFloat) {
                double receiverValue = ((RubyFloat) receiver).getDoubleValue();
                double otherValue = ((RubyFloat) other).getDoubleValue();

                push(runtime.newBoolean(receiverValue > otherValue));
            } else {
                InlineCache ic = byteCode.getInlineCache(op);
                sendVirtual1Arg(runtime, context, ic, self, ">", receiver, other);
            }
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.OPT_GE)
        public void optGeTemplate(int op) {
            IRubyObject other = pop();
            IRubyObject receiver = pop();
            if (other instanceof RubyFixnum && receiver instanceof RubyFixnum) {
                long receiverValue = ((RubyFixnum) receiver).getLongValue();
                long otherValue = ((RubyFixnum) other).getLongValue();

                push(runtime.newBoolean(receiverValue >= otherValue));
            } else if (other instanceof RubyFloat && receiver instanceof RubyFloat) {
                double receiverValue = ((RubyFloat) receiver).getDoubleValue();
                double otherValue = ((RubyFloat) other).getDoubleValue();

                push(runtime.newBoolean(receiverValue >= otherValue));
            } else {
                InlineCache ic = byteCode.getInlineCache(op);
                sendVirtual1Arg(runtime, context, ic, self, ">=", receiver, other);
            }
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.OPT_AREF)
        public void optArefTemplate(int op) {
            InlineCache ic = byteCode.getInlineCache(op);
            sendVirtual1Arg(runtime, context, ic, self, "[]");
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.OPT_ASET)
        public void optAsetTemplate(int op) {
            // YARV will never emit this, for some reason.
            InlineCache ic = byteCode.getInlineCache(op);
            sendVirtual2Args(runtime, context, ic, self, "[]=");
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.OPT_LENGTH)
        public void optLengthTemplate(int op) {
            InlineCache ic = byteCode.getInlineCache(op);
            sendVirtual0Args(runtime, context, ic, self, "length");
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.OPT_SIZE)
        public void optSizeTemplate(int op) {
            InlineCache ic = byteCode.getInlineCache(op);
            sendVirtual0Args(runtime, context, ic, self, "size");
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.OPT_SUCC)
        public void optSuccTemplate(int op) {
            InlineCache ic = byteCode.getInlineCache(op);
            sendVirtual0Args(runtime, context, ic, self, "succ");
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.OPT_NOT)
        public void optNotTemplate(int op) {
            push(pop().isTrue() ? runtime.getFalse() : runtime.getTrue());
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.OPT_REGEXPMATCH1)
        public void optRegExpMatch1Template(int op, int op1) {
            InlineCache ic = byteCode.getInlineCache(op);
            IRubyObject regOp = (IRubyObject) YARVByteCode.getConstant(op1);
            sendVirtual1Arg(runtime, context, ic, self, "=~", regOp, peek());
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.OPT_REGEXPMATCH2)
        public void optRegExpMatch2Template(int op) {
            InlineCache ic = byteCode.getInlineCache(op);
            sendVirtual1Arg(runtime, context, ic, self, "=~");
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.ANSWER)
        public void answerTemplate() {
            push(runtime.newFixnum(42));
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.TRACE)
        public void traceTemplate(int op) {
            System.err.println("Trace: " + op);
        }

        @YARVBYTECODEIMPLEMENTATION(YARVInstructions.THROW)
        public void throwTemplate(int op) {
            IRubyObject throwObj = pop();
            switch (op) {
            case YARVInstructions.RUBY_TAG_RETURN:
                throw context.returnJump(throwObj);
            case YARVInstructions.RUBY_TAG_BREAK:
                RuntimeHelpers.breakJump(context, throwObj);
            default:
                unimplemented(YARVInstructions.THROW);
            }
        }
    }
}
