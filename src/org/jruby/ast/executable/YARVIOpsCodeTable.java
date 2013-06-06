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

import java.lang.reflect.Method;

import com.oracle.max.criutils.HexCodeFile;
import com.sun.max.platform.Platform;
import com.sun.max.program.ProgramError;
import com.sun.max.unsafe.CodePointer;
import com.sun.max.vm.MaxineVM;
import com.sun.max.vm.actor.member.ClassMethodActor;
import com.sun.max.vm.compiler.CallEntryPoint;
import com.sun.max.vm.compiler.CompilationBroker;
import com.sun.max.vm.compiler.RuntimeCompiler;
import com.sun.max.vm.compiler.target.HexCodeFileTool;
import com.sun.max.vm.compiler.target.TargetMethod;

/**
 * @author betasheet
 */
public class YARVIOpsCodeTable {
    private int totalPyBytecodeImplemantationCodeSize;
    private TargetMethod[] bytecodeImplementations;

    static YARVIOpsCodeTable IOpsCodeTable;

    static {
        IOpsCodeTable = new YARVIOpsCodeTable();

        /*
         * statically initialize critical runtime classes to allow C1X to inline
         * more methods when compiling templates
         */
        try {
            new YARVByteCode();
            new YARVMachine();
            new YARVThreadedCodeInterpreter().new ActivationRecord();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private YARVIOpsCodeTable() {
    }

    public static YARVIOpsCodeTable instance() {
        return IOpsCodeTable;
    }

    public void compilePyBytecodeImplementations(Class activationRecordClass) {
        CompilationBroker cb = MaxineVM.vm().compilationBroker;
        RuntimeCompiler optimizingCompiler = cb.optimizingCompiler;
        bytecodeImplementations = new TargetMethod[YARVInstructions.LAST_OPCODE + 1];

        final Method[] bytecodeMethods = activationRecordClass.getDeclaredMethods();

        for (Method method : bytecodeMethods) {
            YARVBYTECODEIMPLEMENTATION anno = method
                    .getAnnotation(YARVBYTECODEIMPLEMENTATION.class);
            if (anno != null) {
                try {
                    ClassMethodActor classMethodActor = ClassMethodActor.fromJava(method);
                    TargetMethod targetMethod = optimizingCompiler.compile(classMethodActor, false,
                            true, null);
                    targetMethod.setAsSubroutine();
                    totalPyBytecodeImplemantationCodeSize += targetMethod.codeLength();
                    // printAssembly(targetMethod,targetMethod.getEntryPoint(CallEntryPoint.OPTIMIZED_ENTRY_POINT));

                    int[] opcodes = anno.value();
                    for (int opcode : opcodes) {
                        bytecodeImplementations[opcode] = targetMethod;
                    }
                } catch (Throwable e) {
                    ProgramError.unexpected(e);
                }
            }
        }
    }

    public TargetMethod getImplementation(int opcode) {
        return bytecodeImplementations[opcode];
    }

    public void printMetrics() {
        System.out.println("Implementations Code Size = " + totalPyBytecodeImplemantationCodeSize
                / 1024 + " kb");
    }

    private void printAssembly(TargetMethod targetMethod, CodePointer startAddress) {
        System.out.println("IOP " + targetMethod.name());
        final Platform platform = Platform.platform();
        HexCodeFile hcf = new HexCodeFile(targetMethod.code(), startAddress.toLong(),
                platform.isa.name(), platform.wordWidth().numberOfBits);
        String s = HexCodeFileTool.toText(hcf);
        System.out.println(s);
    }

}
