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

import static com.sun.cri.ci.CiCallingConvention.Type.JavaCall;
import static com.sun.max.platform.Platform.target;
import static com.sun.max.vm.compiler.CallEntryPoint.OPTIMIZED_ENTRY_POINT;

import com.oracle.max.asm.target.amd64.AMD64;
import com.oracle.max.asm.target.amd64.AMD64Assembler.ConditionFlag;
import com.oracle.max.asm.target.amd64.AMD64MacroAssembler;
import com.oracle.max.criutils.HexCodeFile;
import com.oracle.max.vm.ext.t1x.PatchInfo;
import com.sun.cri.ci.CiAddress;
import com.sun.cri.ci.CiKind;
import com.sun.cri.ci.CiRegister;
import com.sun.cri.ci.CiRegister.RegisterFlag;
import com.sun.cri.ci.CiRegisterConfig;
import com.sun.max.platform.Platform;
import com.sun.max.unsafe.CodePointer;
import com.sun.max.vm.MaxineVM;
import com.sun.max.vm.compiler.target.HexCodeFileTool;
import com.sun.max.vm.compiler.target.SubroutineThreadedCode;
import com.sun.max.vm.compiler.target.SubroutineThreadedCode.SubroutineCall;
import com.sun.max.vm.compiler.target.TargetMethod;
import com.sun.max.vm.runtime.FatalError;

/**
 * @author betasheet
 */
public class YARVThreadedCodeGenerator {

    private final int FRAME_SIZE = 24;

    private final YARVByteCode byteCode;
    private final YARVIOpsCodeTable iOpsCodeTable;
    private final CiRegisterConfig registerConfig;
    private final AMD64MacroAssembler asm;
    private final PatchInfoAMD64 patchInfo;
    private final CiAddress firstStackSlot;
    private final int[] bciToPos;
    private SubroutineThreadedCode subroutineThreadedCode;
    private CiRegister[] locations;

    private static int totalThreadedCodeSize;

    public YARVThreadedCodeGenerator(YARVByteCode byteCode) {
        this.byteCode = byteCode;
        this.iOpsCodeTable = YARVIOpsCodeTable.instance();
        this.registerConfig = MaxineVM.vm().registerConfigs.standard;
        this.asm = new AMD64MacroAssembler(target(), registerConfig);
        this.patchInfo = new PatchInfoAMD64();
        this.bciToPos = new int[byteCode.body.length];
        this.firstStackSlot = new CiAddress(CiKind.Object, AMD64.rsp.asValue(), 8);
        this.locations = registerConfig.getCallingConventionRegisters(JavaCall, RegisterFlag.CPU);
    }

    public TargetMethod generateThreadedCode() {
        subroutineThreadedCode = new SubroutineThreadedCode(byteCode.name, FRAME_SIZE);
        genAdaptorPadding(asm);
        genPrologue();
        // processReenteringImplementation();
        processBytecode();
        int endPos = asm.codeBuffer.position();
        fixup(asm, patchInfo, bciToPos);
        asm.codeBuffer.setPosition(endPos);
        byte[] code = asm.codeBuffer.close(true);
        subroutineThreadedCode.setCode(code);
        subroutineThreadedCode.linkDirectSubroutineCalls();
        totalThreadedCodeSize += subroutineThreadedCode.codeLength();
        
        if (byteCode.getRuntime().getInstanceConfig().isYARVSIPrintThreadedCodeEnabled()) {
            printThreadedCode();
        }
        
        return subroutineThreadedCode;
    }

    private void processBytecode() {
        int next_instr = 0;

        byte[] body = byteCode.body;

        while (next_instr < body.length) {
            bciToPos[next_instr] = asm.codeBuffer.position();
            byte opcode = body[next_instr];

            TargetMethod callee;

            switch (opcode) {

            // branching/jumping etc.
            case YARVInstructions.LEAVE:
                genEpilogue();
                next_instr += 1;
                break;
            case YARVInstructions.JUMP: {
                restoreThisPointer();
                int target = YARVByteCode.getInt(body, next_instr + 1);
                if (next_instr <= target) {
                    emitUnconditionalForwardJump(target);
                } else {
                    emitUnconditionalBackwardsJump(target);
                }
                next_instr += 5;
                break;
            }
            case YARVInstructions.BRANCHIF:
            case YARVInstructions.BRANCHUNLESS: {
                int target = YARVByteCode.getInt(body, next_instr + 1);
                callee = iOpsCodeTable.getImplementation(opcode);
                emitSubroutineCall(callee);
                restoreThisPointer();
                if (next_instr <= target) {
                    emitConditionalForwardJump(target);
                } else {
                    emitConditionalBackwardsJump(target);
                }
                next_instr += 5;
                break;
            }

            // inline cache handling
            case YARVInstructions.ONCEINLINECACHE:
            case YARVInstructions.GETINLINECACHE: {
                int target = YARVByteCode.getInt(body, next_instr + 1);
                callee = iOpsCodeTable.getImplementation(opcode);
                putArgIntoRegister(body, next_instr + 4, 0);
                emitSubroutineCall(callee);
                restoreThisPointer();
                if (next_instr <= target) {
                    emitConditionalForwardJump(target);
                } else {
                    emitConditionalBackwardsJump(target);
                }
                next_instr += 9;
                break;
            }

            case YARVInstructions.SEND:
                // five args
                putArgIntoRegister(body, next_instr, 0);
                putArgIntoRegister(body, next_instr, 1);
                putArgIntoRegister(body, next_instr, 2);
                putArgIntoRegister(body, next_instr, 3);
                putArgIntoRegister(body, next_instr, 4);
                callee = iOpsCodeTable.getImplementation(opcode);
                emitSubroutineCall(callee);
                next_instr += 21;
                break;
            case YARVInstructions.DEFINECLASS:
                // three args
                putArgIntoRegister(body, next_instr, 0);
                putArgIntoRegister(body, next_instr, 1);
                putArgIntoRegister(body, next_instr, 2);
                callee = iOpsCodeTable.getImplementation(opcode);
                emitSubroutineCall(callee);
                next_instr += 13;
                break;
            case YARVInstructions.GETDYNAMIC:
            case YARVInstructions.SETDYNAMIC:
            case YARVInstructions.TOREGEXP:
            case YARVInstructions.EXPANDARRAY:
            case YARVInstructions.OPT_REGEXPMATCH1:
                // two args
                putArgIntoRegister(body, next_instr, 0);
                putArgIntoRegister(body, next_instr, 1);
                callee = iOpsCodeTable.getImplementation(opcode);
                emitSubroutineCall(callee);
                next_instr += 9;
                break;
            case YARVInstructions.GETGLOBAL:
            case YARVInstructions.SETGLOBAL:
            case YARVInstructions.GETLOCAL:
            case YARVInstructions.SETLOCAL:
            case YARVInstructions.GETINSTANCEVARIABLE:
            case YARVInstructions.SETINSTANCEVARIABLE:
            case YARVInstructions.GETCLASSVARIABLE:
            case YARVInstructions.SETCLASSVARIABLE:
            case YARVInstructions.GETCONSTANT:
            case YARVInstructions.SETCONSTANT:
            case YARVInstructions.PUTISEQ:
            case YARVInstructions.PUTOBJECT:
            case YARVInstructions.PUTSPECIALOBJECT:
            case YARVInstructions.PUTSTRING:
            case YARVInstructions.CONCATSTRINGS:
            case YARVInstructions.NEWARRAY:
            case YARVInstructions.DUPARRAY:
            case YARVInstructions.NEWHASH:
            case YARVInstructions.NEWRANGE:
            case YARVInstructions.DUPN:
            case YARVInstructions.TOPN:
            case YARVInstructions.SETN:
            case YARVInstructions.OPT_PLUS:
            case YARVInstructions.OPT_MINUS:
            case YARVInstructions.OPT_MULT:
            case YARVInstructions.OPT_DIV:
            case YARVInstructions.OPT_MOD:
            case YARVInstructions.OPT_EQ:
            case YARVInstructions.OPT_NEQ:
            case YARVInstructions.OPT_LT:
            case YARVInstructions.OPT_LE:
            case YARVInstructions.OPT_LTLT:
            case YARVInstructions.OPT_GT:
            case YARVInstructions.OPT_GE:
            case YARVInstructions.OPT_AREF:
            case YARVInstructions.OPT_ASET:
            case YARVInstructions.OPT_LENGTH:
            case YARVInstructions.OPT_SIZE:
            case YARVInstructions.OPT_SUCC:
            case YARVInstructions.OPT_NOT:
            case YARVInstructions.OPT_REGEXPMATCH2:
            case YARVInstructions.TRACE:
            case YARVInstructions.THROW:
            case YARVInstructions.SETINLINECACHE:
                // one arg
                putArgIntoRegister(body, next_instr, 0);
                callee = iOpsCodeTable.getImplementation(opcode);
                emitSubroutineCall(callee);
                next_instr += 5;
                break;
            case YARVInstructions.NOP:
            case YARVInstructions.PUTNIL:
            case YARVInstructions.PUTSELF:
            case YARVInstructions.TOSTRING:
            case YARVInstructions.POP:
            case YARVInstructions.DUP:
            case YARVInstructions.SWAP:
            case YARVInstructions.ANSWER:
            default:
                // default case (no arg)
                callee = iOpsCodeTable.getImplementation(opcode);
                emitSubroutineCall(callee);
                next_instr += 1;
                break;
            }

            restoreThisPointer();
        }
    }

    private void genPrologue() {
        // allocate frame
        asm.subq(AMD64.rsp, FRAME_SIZE);
        // put the this pointer into the first stack slot
        asm.movq(firstStackSlot, AMD64.rdi);
    }

    private void genEpilogue() {
        // deallocate frame
        
        // trace frame pointer
        //asm.movq(locations[1], AMD64.rsp);
        //TargetMethod callee = iOpsCodeTable.getImplementation(YARVInstructions.TRACE);
        //emitSubroutineCall(callee);
        
        asm.addq(AMD64.rsp, FRAME_SIZE);
        asm.ret(0);
    }

    private void genAdaptorPadding(AMD64MacroAssembler asm) {
        // Emit 8 bytes of nop for stackwalker
        for (int i = 0; i < 8; i++) {
            asm.nop();
        }
    }

    private void emitSubroutineCall(TargetMethod callee) {
        CodePointer calleeEntryPoint = callee.getEntryPoint(OPTIMIZED_ENTRY_POINT);
        subroutineThreadedCode.addSubroutineCall(new SubroutineCall(asm.codeBuffer.position(),
                calleeEntryPoint));
        asm.call();
    }

    private void restoreThisPointer() {
        asm.movq(locations[0], firstStackSlot);
    }

    private void putArgIntoRegister(byte[] body, int instr, int argNum) {
        // read param from byteCode (getInt)
        // theoretically also long possible but not used
        int intVal = YARVByteCode.getInt(body, instr + 1 + argNum * 4);

        // emit move immediate
        asm.movl(locations[argNum + 1], intVal);
    }

    private int emitUnconditionalForwardJump(int targetBCI) {
        int position = patchInfo.addJMP(asm.codeBuffer.position(), targetBCI);
        asm.jmp(0, true);
        return position;
    }

    private void emitUnconditionalBackwardsJump(int targetBCI) {
        int target = bciToPos[targetBCI];
        asm.jmp(target, false);
    }

    private int emitConditionalForwardJump(int targetBCI) {
        asm.cmpq(AMD64.rax, 0);
        int position = patchInfo.addJCC(ConditionFlag.notEqual, asm.codeBuffer.position(),
                targetBCI);
        asm.jcc(ConditionFlag.notEqual, 0, true);
        return position;
    }

    private void emitConditionalBackwardsJump(int targetBCI) {
        int target = bciToPos[targetBCI];
        asm.cmpq(AMD64.rax, 0);
        asm.jcc(ConditionFlag.notEqual, target, false);
    }

    private void printThreadedCode() {
        final Platform platform = Platform.platform();
        long startAddress = this.subroutineThreadedCode.codeStart().toLong();
        HexCodeFile hcf = new HexCodeFile(this.subroutineThreadedCode.code(), startAddress,
                platform.isa.name(), platform.wordWidth().numberOfBits);
        String s = HexCodeFileTool.toText(hcf);
// HexCodeFileDis dis = new HexCodeFileDis(false);
// dis.process(hcf, null);
        System.out.println(s);
    }

    public void printMetrics() {
        System.out.println("Subroutine Threaded Code Size = " + totalThreadedCodeSize / 1024
                + " kb");
    }

    /*
     * PatchInfoAMD64 is taken from AMD64T1XCompilation
     */
    static class PatchInfoAMD64 extends PatchInfo {

        /**
         * Denotes a conditional jump patch. Encoding:
         * {@code cc, pos, targetBCI}.
         */
        static final int JCC = 0;

        /**
         * Denotes an unconditional jump patch. Encoding: {@code pos, targetBCI}
         * .
         */
        static final int JMP = 1;

        int addJCC(ConditionFlag cc, int pos, int targetBCI) {
            ensureCapacity(size + 4);
            data[size++] = JCC;
            data[size++] = cc.ordinal();
            data[size++] = pos;
            int position = size;
            data[size++] = targetBCI;
            return position;
        }

        int addJMP(int pos, int targetBCI) {
            ensureCapacity(size + 3);
            data[size++] = JMP;
            data[size++] = pos;
            int position = size;
            data[size++] = targetBCI;
            return position;
        }

        void retrieveTargetBCI(int pos, int targetBCI) {
            data[pos] = targetBCI;
        }
    }

    protected static void fixup(AMD64MacroAssembler asm, PatchInfo patchInfo, int[] bciToPos) {
        int i = 0;
        int[] data = patchInfo.data;

        while (i < patchInfo.size) {
            int tag = data[i++];
            if (tag == PatchInfoAMD64.JMP) {
                int pos = data[i++];
                int targetBCI = data[i++];
                int target = bciToPos[targetBCI];
                assert target != 0;
                asm.codeBuffer.setPosition(pos);
                asm.jmp(target, true);
            } else if (tag == PatchInfoAMD64.JCC) {
                ConditionFlag cc = ConditionFlag.values[data[i++]];
                int pos = data[i++];
                int targetBCI = data[i++];
                int target = bciToPos[targetBCI];
                assert target != 0;
                asm.codeBuffer.setPosition(pos);
                asm.jcc(cc, target, true);
            } else {
                throw FatalError.unexpected(String.valueOf(tag));
            }
        }
    }

}
