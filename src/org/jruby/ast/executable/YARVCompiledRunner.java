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
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyFile;
import org.jruby.RubyHash;
import org.jruby.RubyNil;
import org.jruby.RubyNumeric;
import org.jruby.RubyString;
import org.jruby.RubySymbol;
import org.jruby.parser.StaticScope;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;

/**
 * @author <a href="mailto:ola.bini@ki.se">Ola Bini</a>
 */
public class YARVCompiledRunner {
    private Ruby runtime;

    private YARVByteCode byteCode;

    public YARVCompiledRunner(Ruby runtime, InputStream in, String filename) {
        this.runtime = runtime;
        byte[] first = new byte[4];
        try {
            in.read(first);
            if (first[0] != 'R' || first[1] != 'B' || first[2] != 'C' || first[3] != 'M') {
                throw new RuntimeException("File is not a compiled YARV file");
            }
            RubyFile f = new RubyFile(runtime, filename, in);
            IRubyObject arr = runtime.getMarshal().callMethod(runtime.getCurrentContext(), "load",
                    f);
            byteCode = transformIntoByteCode(arr);
        } catch (IOException e) {
            throw new RuntimeException("Couldn't read from source", e);
        }
    }

    public YARVCompiledRunner(Ruby runtime, YARVByteCode byteCode) {
        this.runtime = runtime;
        this.byteCode = byteCode;
    }

    public IRubyObject run() {
        ThreadContext context = runtime.getCurrentContext();
        StaticScope scope = runtime.getStaticScopeFactory().newLocalScope(null, byteCode.locals);
        context.setFileAndLine(byteCode.filename, -1);
        return YARVMachine.getInstance().exec(context, scope, byteCode);
    }

    private YARVByteCode transformIntoByteCode(IRubyObject arr) {
        if (!(arr instanceof RubyArray)) {
            throw new RuntimeException("Error when reading compiled YARV file");
        }

        Map jumps = new HashMap();
        Map labels = new HashMap();

        YARVByteCode byteCode = new YARVByteCode(runtime, runtime.getYarvByteCode());
        Iterator internal = (((RubyArray) arr).getList()).iterator();
        byteCode.magic = internal.next().toString();
        byteCode.major = RubyNumeric.fix2int((IRubyObject) internal.next());
        byteCode.minor = RubyNumeric.fix2int((IRubyObject) internal.next());
        byteCode.format_type = RubyNumeric.fix2int((IRubyObject) internal.next());
        IRubyObject misc = (IRubyObject) internal.next();
        if (misc.isNil()) {
            byteCode.misc = null;
        } else {
            byteCode.misc = misc;
            if (misc instanceof RubyHash) {
                Object local_size = ((RubyHash) misc).get(RubySymbol.newSymbol(runtime,
                        "local_size"));
                if (local_size != null) {
                    byteCode.local_size = ((Long) local_size).intValue();
                }
            }
        }
        byteCode.name = internal.next().toString();
        byteCode.filename = internal.next().toString();
        byteCode.filefullpath = internal.next().toString();
        byteCode.line = RubyNumeric.fix2int((IRubyObject) internal.next());
        byteCode.type = internal.next().toString();
        byteCode.locals = toStringArray((IRubyObject) internal.next());
        if (byteCode.local_size > byteCode.locals.length) {
            String[] oldLocals = byteCode.locals;
            byteCode.locals = new String[byteCode.local_size];
            System.arraycopy(oldLocals, 0, byteCode.locals, 0, oldLocals.length);
            for (int i = oldLocals.length; i < byteCode.local_size; i++) {
                byteCode.locals[i] = "localvar" + i + "_" + RubyNumeric.fix2int(byteCode.id());
            }
        }
        IRubyObject argo = (IRubyObject) internal.next();
        if (argo instanceof RubyArray) {
            List arglist = ((RubyArray) argo).getList();
            byteCode.args_argc = RubyNumeric.fix2int((IRubyObject) arglist.get(0));
            byteCode.args_opt_labels = toStringArray((IRubyObject) arglist.get(1));
            byteCode.args_post_len = RubyNumeric.fix2int((IRubyObject) arglist.get(2));
            byteCode.args_post_start = RubyNumeric.fix2int((IRubyObject) arglist.get(3));
            byteCode.args_rest = RubyNumeric.fix2int((IRubyObject) arglist.get(4));
            byteCode.args_block = RubyNumeric.fix2int((IRubyObject) arglist.get(5));
            byteCode.args_simple = RubyNumeric.fix2int((IRubyObject) arglist.get(6));
        } else {
            byteCode.args_argc = RubyNumeric.fix2int(argo);
        }

        byteCode.exception = getExceptionInformation((IRubyObject) internal.next());

        List bodyl = ((RubyArray) internal.next()).getList();
        for (Iterator iter = bodyl.iterator(); iter.hasNext();) {
            IRubyObject is = (IRubyObject) iter.next();
            if (is instanceof RubyArray) {
                intoInstruction((RubyArray) is, byteCode, jumps);
            } else if (is instanceof RubySymbol) {
                labels.put(is.toString(), byteCode.getNextInstructionPosition());
            }
        }

        byteCode.closeBuffer();

        for (Iterator iter = jumps.entrySet().iterator(); iter.hasNext();) {
            Map.Entry<Integer, String> entry = (Map.Entry<Integer, String>) iter.next();
            byteCode.setJumpTarget(entry.getKey(), (Integer) labels.get(entry.getValue()));
        }

        if (YARVMachine.threadedCode) {
            YARVThreadedCodeGenerator tcg = new YARVThreadedCodeGenerator(byteCode);
            byteCode.targetMethod = tcg.generateThreadedCode();
        }

        return byteCode;
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

    private void intoInstruction(RubyArray obj, YARVByteCode byteCode, Map jumps) {
        List internal = obj.getList();
        String name = internal.get(0).toString();
        byte instruction = YARVInstructions.instruction(name);
        if (instruction != YARVInstructions.TRACE && instruction != YARVInstructions.NOP) {
            int instructionPos = byteCode.pushInstruction(instruction);
            if (internal.size() > 1) {
                IRubyObject first = (IRubyObject) internal.get(1);
                if (instruction == YARVInstructions.PUTOBJECT
                        || instruction == YARVInstructions.OPT_REGEXPMATCH1
                        || instruction == YARVInstructions.DUPARRAY) {
                    byteCode.push(first);
                } else if (isJump(instruction)) {
                    jumps.put(instructionPos, first.toString());
                    byteCode.push(-1); // jump location: will be updated later
                } else if (first instanceof RubyString || first instanceof RubySymbol) {
                    byteCode.push(first.toString());
                } else if (first instanceof RubyNumeric) {
                    byteCode.push(RubyNumeric.fix2int(first));
                }

                if (instruction == YARVInstructions.GETINLINECACHE
                        || instruction == YARVInstructions.ONCEINLINECACHE
                        || instruction == YARVInstructions.GETDYNAMIC
                        || instruction == YARVInstructions.SETDYNAMIC
                        || instruction == YARVInstructions.TOREGEXP
                        || instruction == YARVInstructions.EXPANDARRAY) {
                    byteCode.push(RubyNumeric.fix2int((IRubyObject) internal.get(2)));
                } else if (instruction == YARVInstructions.SEND) {
                    byteCode.push(RubyNumeric.fix2int((IRubyObject) internal.get(2)));
                    if (!((IRubyObject) internal.get(3) instanceof RubyNil)) {
                        byteCode.push(transformIntoByteCode((IRubyObject) internal.get(3)));
                    } else {
                        byteCode.push(null);
                    }
                    byteCode.push(RubyNumeric.fix2int((IRubyObject) internal.get(4)));
                    byteCode.push(RubyNumeric.fix2int((IRubyObject) internal.get(5)));
                } else if (instruction == YARVInstructions.PUTISEQ) {
                    byteCode.push(transformIntoByteCode(first));
                } else if (instruction == YARVInstructions.DEFINECLASS) {
                    byteCode.push(transformIntoByteCode((IRubyObject) internal.get(2)));
                    byteCode.push(RubyNumeric.fix2int((IRubyObject) internal.get(3)));
                }
            }
        }
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
