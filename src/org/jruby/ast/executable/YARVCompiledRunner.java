/*****
 * BEGIN LICENSE BLOCK ***** Version: CPL 1.0/GPL 2.0/LGPL 2.1 The contents of
 * this file are subject to the Common Public License Version 1.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.eclipse.org/legal/cpl-v10.html Software distributed under the
 * License is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND,
 * either express or implied. See the License for the specific language
 * governing rights and limitations under the License. Copyright (C) 2007 Ola
 * Bini <ola@ologix.com> Alternatively, the contents of this file may be used
 * under the terms of either of the GNU General Public License Version 2 or
 * later (the "GPL"), or the GNU Lesser General Public License Version 2.1 or
 * later (the "LGPL"), in which case the provisions of the GPL or the LGPL are
 * applicable instead of those above. If you wish to allow use of your version
 * of this file only under the terms of either the GPL or the LGPL, and not to
 * allow others to use your version of this file under the terms of the CPL,
 * indicate your decision by deleting the provisions above and replace them with
 * the notice and other provisions required by the GPL or the LGPL. If you do
 * not delete the provisions above, a recipient may use your version of this
 * file under the terms of any one of the CPL, the GPL or the LGPL. END LICENSE
 * BLOCK
 *****/
package org.jruby.ast.executable;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyClass;
import org.jruby.RubyFile;
import org.jruby.RubyHash;
import org.jruby.RubyNil;
import org.jruby.RubyNumeric;
import org.jruby.RubyString;
import org.jruby.RubySymbol;
import org.jruby.ast.executable.YARVMachine.InstructionSequence;
import org.jruby.parser.StaticScope;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class YARVCompiledRunner {
    private Ruby runtime;

    private YARVMachine.InstructionSequence iseq;
    private RubyClass iseqClass;

    public YARVCompiledRunner(Ruby runtime, InputStream in, String filename) {
        this.runtime = runtime;
        this.iseqClass = InstructionSequence.createInstructionSequence(runtime);
        byte[] first = new byte[4];
        try {
            in.read(first);
            if (first[0] != 'R' || first[1] != 'B' || first[2] != 'C' || first[3] != 'M') {
                throw new RuntimeException("File is not a compiled YARV file");
            }
            RubyFile f = new RubyFile(runtime, filename, in);
            IRubyObject arr = runtime.getMarshal().callMethod(runtime.getCurrentContext(), "load",
                    f);
            iseq = transformIntoSequence(arr);
        } catch (IOException e) {
            throw new RuntimeException("Couldn't read from source", e);
        }
    }

    public YARVCompiledRunner(Ruby runtime, YARVMachine.InstructionSequence iseq) {
        this.runtime = runtime;
        this.iseq = iseq;
    }

    public IRubyObject run() {
        ThreadContext context = runtime.getCurrentContext();
        StaticScope scope = runtime.getStaticScopeFactory().newLocalScope(null, iseq.locals);
        context.setFileAndLine(iseq.filename, -1);
        return YARVMachine.getInstance().exec(context, scope, iseq);
    }

    private YARVMachine.InstructionSequence transformIntoSequence(IRubyObject arr) {
        if (!(arr instanceof RubyArray)) {
            throw new RuntimeException("Error when reading compiled YARV file");
        }

        Map jumps = new IdentityHashMap();
        Map labels = new HashMap();

        YARVMachine.InstructionSequence seq = new YARVMachine.InstructionSequence(runtime,
                iseqClass, null, null, null);
        Iterator internal = (((RubyArray) arr).getList()).iterator();
        seq.magic = internal.next().toString();
        seq.major = RubyNumeric.fix2int((IRubyObject) internal.next());
        seq.minor = RubyNumeric.fix2int((IRubyObject) internal.next());
        seq.format_type = RubyNumeric.fix2int((IRubyObject) internal.next());
        IRubyObject misc = (IRubyObject) internal.next();
        if (misc.isNil()) {
            seq.misc = null;
        } else {
            seq.misc = misc;
            if (misc instanceof RubyHash) {
                Object local_size = ((RubyHash) misc).get(RubySymbol.newSymbol(runtime,
                        "local_size"));
                if (local_size != null) {
                    seq.local_size = ((Long) local_size).intValue();
                }
            }
        }
        seq.name = internal.next().toString();
        seq.filename = internal.next().toString();
        seq.filefullpath = internal.next().toString();
        seq.line = RubyNumeric.fix2int((IRubyObject) internal.next());
        seq.type = internal.next().toString();
        seq.locals = toStringArray((IRubyObject) internal.next());
        if (seq.local_size > seq.locals.length) {
            String[] oldLocals = seq.locals;
            seq.locals = new String[seq.local_size];
            System.arraycopy(oldLocals, 0, seq.locals, 0, oldLocals.length);
            for (int i = oldLocals.length; i < seq.local_size; i++) {
                seq.locals[i] = "localvar" + i + "_" + RubyNumeric.fix2int(seq.id());
            }
        }
        IRubyObject argo = (IRubyObject) internal.next();
        if (argo instanceof RubyArray) {
            List arglist = ((RubyArray) argo).getList();
            seq.args_argc = RubyNumeric.fix2int((IRubyObject) arglist.get(0));
            seq.args_opt_labels = toStringArray((IRubyObject) arglist.get(1));
            seq.args_post_len = RubyNumeric.fix2int((IRubyObject) arglist.get(2));
            seq.args_post_start = RubyNumeric.fix2int((IRubyObject) arglist.get(3));
            seq.args_rest = RubyNumeric.fix2int((IRubyObject) arglist.get(4));
            seq.args_block = RubyNumeric.fix2int((IRubyObject) arglist.get(5));
            seq.args_simple = RubyNumeric.fix2int((IRubyObject) arglist.get(6));
        } else {
            seq.args_argc = RubyNumeric.fix2int(argo);
        }

        seq.exception = getExceptionInformation((IRubyObject) internal.next());

        List bodyl = ((RubyArray) internal.next()).getList();
        YARVMachine.Instruction[] body = new YARVMachine.Instruction[bodyl.size()];
        int real = 0;
        int i = 0;
        for (Iterator iter = bodyl.iterator(); iter.hasNext(); i++) {
            IRubyObject is = (IRubyObject) iter.next();
            if (is instanceof RubyArray) {
                body[real] = intoInstruction((RubyArray) is, real, seq, jumps);
                real++;
            } else if (is instanceof RubySymbol) {
                labels.put(is.toString(), new Integer(real + 1));
            }
        }
        YARVMachine.Instruction[] nbody = new YARVMachine.Instruction[real];
        System.arraycopy(body, 0, nbody, 0, real);
        seq.body = nbody;

        for (Iterator iter = jumps.keySet().iterator(); iter.hasNext();) {
            YARVMachine.Instruction k = (YARVMachine.Instruction) iter.next();
            k.l_op0 = ((Integer) labels.get(jumps.get(k))).intValue() - 1;
        }

        return seq;
    }

    private String[] toStringArray(IRubyObject obj) {
        if (obj.isNil()) {
            return new String[0];
        } else {
            List l = ((RubyArray) obj).getList();
            String[] s = new String[l.size()];
            int i = 0;
            for (Iterator iter = l.iterator(); iter.hasNext(); i++) {
                s[i] = iter.next().toString();
            }
            return s;
        }
    }

    private YARVMachine.Instruction intoInstruction(RubyArray obj, int n,
            YARVMachine.InstructionSequence iseq, Map jumps) {
        List internal = obj.getList();
        String name = internal.get(0).toString();
        int instruction = YARVMachine.instruction(name);
        YARVMachine.Instruction i = new YARVMachine.Instruction(instruction);
        if (internal.size() > 1) {
            IRubyObject first = (IRubyObject) internal.get(1);
            if (instruction == YARVInstructions.PUTOBJECT
                    || instruction == YARVInstructions.OPT_REGEXPMATCH1
                    || instruction == YARVInstructions.DUPARRAY) {
                i.o_op0 = first;
            } else if (first instanceof RubyString || first instanceof RubySymbol) {
                i.s_op0 = first.toString();
            } else if (first instanceof RubyNumeric) {
                i.l_op0 = RubyNumeric.fix2long(first);
            }

            if (instruction == YARVInstructions.GETLOCAL
                    || instruction == YARVInstructions.SETLOCAL) {
                i.i_op1 = -1;
            }

            if (instruction == YARVInstructions.GETINLINECACHE
                    || instruction == YARVInstructions.ONCEINLINECACHE
                    || instruction == YARVInstructions.GETDYNAMIC
                    || instruction == YARVInstructions.SETDYNAMIC
                    || instruction == YARVInstructions.TOREGEXP
                    || instruction == YARVInstructions.EXPANDARRAY) {
                i.l_op1 = RubyNumeric.fix2long((IRubyObject) internal.get(2));
            } else if (instruction == YARVInstructions.SEND) {
                i.i_op1 = RubyNumeric.fix2int((IRubyObject) internal.get(2));
                i.i_op3 = RubyNumeric.fix2int((IRubyObject) internal.get(4));
                if (!((IRubyObject) internal.get(3) instanceof RubyNil)) {
                    i.iseq_op = transformIntoSequence((IRubyObject) internal.get(3));
                }
            } else if (instruction == YARVInstructions.PUTISEQ) {
                i.iseq_op = transformIntoSequence((IRubyObject) internal.get(1));
            } else if (instruction == YARVInstructions.DEFINECLASS) {
                i.iseq_op = transformIntoSequence((IRubyObject) internal.get(2));
                i.i_op2 = RubyNumeric.fix2int((IRubyObject) internal.get(3));
            }

            if (isJump(instruction)) {
                i.index = n;
                jumps.put(i, internal.get(1).toString());
            }
        }
        return i;
    }

    private boolean isJump(int i) {
        return i == YARVInstructions.JUMP || i == YARVInstructions.BRANCHIF
                || i == YARVInstructions.BRANCHUNLESS || i == YARVInstructions.GETINLINECACHE
                || i == YARVInstructions.ONCEINLINECACHE;
    }

    private Object[] getExceptionInformation(IRubyObject obj) {
        // System.err.println(obj.callMethod(runtime.getCurrentContext(),"inspect"));
        return new Object[0];
    }
}// YARVCompiledRunner
