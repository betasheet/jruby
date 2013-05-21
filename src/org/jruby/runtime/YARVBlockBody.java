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
package org.jruby.runtime;

import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyModule;
import org.jruby.ast.executable.YARVByteCode;
import org.jruby.ast.executable.YARVMachine;
import org.jruby.exceptions.JumpException;
import org.jruby.internal.runtime.methods.YARVMethod;
import org.jruby.parser.StaticScope;
import org.jruby.runtime.Block.Type;
import org.jruby.runtime.builtin.IRubyObject;

/**
 * @author betasheet
 */
public class YARVBlockBody extends ContextAwareBlockBody {

    private YARVByteCode byteCode;

    public YARVBlockBody(StaticScope scope, Arity arity, int argumentType, YARVByteCode byteCode) {
        super(scope, arity, argumentType);

        this.byteCode = byteCode;
    }

    @Override
    public IRubyObject yield(ThreadContext context, IRubyObject value, Binding binding, Type type) {
        return yield(context, value, binding, type, Block.NULL_BLOCK);
    }

    @Override
    public IRubyObject yield(ThreadContext context, IRubyObject value, IRubyObject self,
            RubyModule klass, boolean aValue, Binding binding, Type type) {
        return yield(context, value, self, klass, aValue, binding, type, Block.NULL_BLOCK);
    }

    @Override
    public IRubyObject yield(ThreadContext context, IRubyObject value, Binding binding,
            Block.Type type, Block block) {
        IRubyObject self = prepareSelf(binding);
        Visibility oldVis = binding.getFrame().getVisibility();
        DynamicScope localScope = context.getCurrentScope().localScope;
        Frame lastFrame = pre(context, null, binding);
        context.getCurrentScope().localScope = localScope;

        try {
            prepareArguments(context, value, false, context.getRuntime());

            return evalBlockBody(context, binding, self);
        } catch (JumpException.NextJump nj) {
            return handleNextJump(context, nj, type);
        } finally {
            post(context, binding, oldVis, lastFrame);
        }
    }

    @Override
    public IRubyObject yield(ThreadContext context, IRubyObject value, IRubyObject self,
            RubyModule klass, boolean alreadyArray, Binding binding, Block.Type type, Block block) {
        if (klass == null) {
            self = prepareSelf(binding);
        }

        Visibility oldVis = binding.getFrame().getVisibility();
        DynamicScope localScope = context.getCurrentScope().localScope;
        Frame lastFrame = pre(context, klass, binding);
        context.getCurrentScope().localScope = localScope;

        try {
            prepareArguments(context, value, alreadyArray, context.getRuntime());

            return evalBlockBody(context, binding, self);
        } catch (JumpException.NextJump nj) {
            return handleNextJump(context, nj, type);
        } finally {
            post(context, binding, oldVis, lastFrame);
        }
    }

    private void prepareArguments(ThreadContext context, IRubyObject value, boolean alreadyArray,
            Ruby runtime) {
        // TODO arg size checks
        if (argumentType != ZERO_ARGS) {
            DynamicScope scope = context.getCurrentScope();
            // TODO only expand array if we have more than one argument to expand it to
            // TODO make sure all border cases are supported (rest args, ...)
            if (byteCode.args_argc > 1 && value instanceof RubyArray) {
                IRubyObject[] args = YARVMethod.prepareArguments(byteCode, context, runtime,
                        ((RubyArray) value).toJavaArrayUnsafe());

                // Why not setArgValues
                scope.setArgValues(args, args.length);
            } else {
                scope.setArgValues(value);
            }
        }
    }

    private IRubyObject evalBlockBody(ThreadContext context, Binding binding, IRubyObject self) {
        // This while loop is for restarting the block call in case a 'redo' fires.
        while (true) {
            try {
                return YARVMachine.getInstance().exec(context, self, byteCode);
            } catch (JumpException.RedoJump rj) {
                context.pollThreadEvents();
                // do nothing, allow loop to redo
            } catch (StackOverflowError soe) {
                throw context.runtime.newSystemStackError("stack level too deep", soe);
            }
        }
    }

    private IRubyObject prepareSelf(Binding binding) {
        IRubyObject self = binding.getSelf();
        binding.getFrame().setSelf(self);

        return self;
    }

    // TODO this is just copied from InterpretedBlock for now. might have to be
    // handled differently here.
    private IRubyObject handleNextJump(ThreadContext context, JumpException.NextJump nj,
            Block.Type type) {
        return nj.getValue() == null ? context.runtime.getNil() : (IRubyObject) nj.getValue();
    }

    @Override
    public String getFile() {
        return byteCode.filename;
    }

    @Override
    public int getLine() {
        return byteCode.line;
    }

}
