/***** BEGIN LICENSE BLOCK *****
 * Version: CPL 1.0/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Common Public
 * License Version 1.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.eclipse.org/legal/cpl-v10.html
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 * Copyright (C) 2006 Charles O Nutter <headius@headius.com>
 * Copyright (C) 2007 Ola Bini <ola@ologix.com>
 * 
 * Alternatively, the contents of this file may be used under the terms of
 * either of the GNU General Public License Version 2 or later (the "GPL"),
 * or the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the CPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the CPL, the GPL or the LGPL.
 ***** END LICENSE BLOCK *****/
package org.jruby.ast.executable;

import java.util.Map;
import java.util.HashMap;

/**
 * AUTOGENERATED. Change template, not generated file.
 */
public abstract class YARVInstructions {
    public static final byte NOP = 0;
    public static final byte GETLOCAL = 1;
    public static final byte SETLOCAL = 2;
    public static final byte GETSPECIAL = 3;
    public static final byte SETSPECIAL = 4;
    public static final byte GETDYNAMIC = 5;
    public static final byte SETDYNAMIC = 6;
    public static final byte GETINSTANCEVARIABLE = 7;
    public static final byte SETINSTANCEVARIABLE = 8;
    public static final byte GETCLASSVARIABLE = 9;
    public static final byte SETCLASSVARIABLE = 10;
    public static final byte GETCONSTANT = 11;
    public static final byte SETCONSTANT = 12;
    public static final byte GETGLOBAL = 13;
    public static final byte SETGLOBAL = 14;
    public static final byte PUTNIL = 15;
    public static final byte PUTSELF = 16;
    public static final byte PUTOBJECT = 17;
    public static final byte PUTSPECIALOBJECT = 18;
    public static final byte PUTISEQ = 19;
    public static final byte PUTSTRING = 20;
    public static final byte CONCATSTRINGS = 21;
    public static final byte TOSTRING = 22;
    public static final byte TOREGEXP = 23;
    public static final byte NEWARRAY = 24;
    public static final byte DUPARRAY = 25;
    public static final byte EXPANDARRAY = 26;
    public static final byte CONCATARRAY = 27;
    public static final byte SPLATARRAY = 28;
    public static final byte CHECKINCLUDEARRAY = 29;
    public static final byte NEWHASH = 30;
    public static final byte NEWRANGE = 31;
    public static final byte POP = 32;
    public static final byte DUP = 33;
    public static final byte DUPN = 34;
    public static final byte SWAP = 35;
    public static final byte REPUT = 36;
    public static final byte TOPN = 37;
    public static final byte SETN = 38;
    public static final byte ADJUSTSTACK = 39;
    public static final byte DEFINED = 40;
    public static final byte TRACE = 41;
    public static final byte DEFINECLASS = 42;
    public static final byte SEND = 43;
    public static final byte INVOKESUPER = 44;
    public static final byte INVOKEBLOCK = 45;
    public static final byte LEAVE = 46;
    public static final byte FINISH = 47;
    public static final byte THROW = 48;
    public static final byte JUMP = 49;
    public static final byte BRANCHIF = 50;
    public static final byte BRANCHUNLESS = 51;
    public static final byte GETINLINECACHE = 52;
    public static final byte ONCEINLINECACHE = 53;
    public static final byte SETINLINECACHE = 54;
    public static final byte OPT_CASE_DISPATCH = 55;
    public static final byte OPT_CHECKENV = 56;
    public static final byte OPT_PLUS = 57;
    public static final byte OPT_MINUS = 58;
    public static final byte OPT_MULT = 59;
    public static final byte OPT_DIV = 60;
    public static final byte OPT_MOD = 61;
    public static final byte OPT_EQ = 62;
    public static final byte OPT_NEQ = 63;
    public static final byte OPT_LT = 64;
    public static final byte OPT_LE = 65;
    public static final byte OPT_GT = 66;
    public static final byte OPT_GE = 67;
    public static final byte OPT_LTLT = 68;
    public static final byte OPT_AREF = 69;
    public static final byte OPT_ASET = 70;
    public static final byte OPT_LENGTH = 71;
    public static final byte OPT_SIZE = 72;
    public static final byte OPT_SUCC = 73;
    public static final byte OPT_NOT = 74;
    public static final byte OPT_REGEXPMATCH1 = 75;
    public static final byte OPT_REGEXPMATCH2 = 76;
    public static final byte OPT_CALL_C_FUNCTION = 77;
    public static final byte BITBLT = 78;
    public static final byte ANSWER = 79;
    public static final byte SEND_NO_ARG = 80;
    public static final byte SEND_ONE_ARG = 81;
    public static final byte SEND_TWO_ARG = 82;
    public static final byte SEND_THREE_ARG = 83;
    public static final byte SEND_MANY_ARG = 84;
    public static final byte SEND_NO_ARG_BLOCK = 85;
    public static final byte SEND_ONE_ARG_BLOCK = 86;
    public static final byte SEND_TWO_ARG_BLOCK = 87;
    public static final byte SEND_THREE_ARG_BLOCK = 88;
    public static final byte SEND_MANY_ARG_BLOCK = 89;

    public static final Map INSTS_TO_INDEX = new HashMap();
    static {
        INSTS_TO_INDEX.put("nop", new Byte((byte) 0));
        INSTS_TO_INDEX.put("getlocal", new Byte((byte) 1));
        INSTS_TO_INDEX.put("setlocal", new Byte((byte) 2));
        INSTS_TO_INDEX.put("getspecial", new Byte((byte) 3));
        INSTS_TO_INDEX.put("setspecial", new Byte((byte) 4));
        INSTS_TO_INDEX.put("getdynamic", new Byte((byte) 5));
        INSTS_TO_INDEX.put("setdynamic", new Byte((byte) 6));
        INSTS_TO_INDEX.put("getinstancevariable", new Byte((byte) 7));
        INSTS_TO_INDEX.put("setinstancevariable", new Byte((byte) 8));
        INSTS_TO_INDEX.put("getclassvariable", new Byte((byte) 9));
        INSTS_TO_INDEX.put("setclassvariable", new Byte((byte) 10));
        INSTS_TO_INDEX.put("getconstant", new Byte((byte) 11));
        INSTS_TO_INDEX.put("setconstant", new Byte((byte) 12));
        INSTS_TO_INDEX.put("getglobal", new Byte((byte) 13));
        INSTS_TO_INDEX.put("setglobal", new Byte((byte) 14));
        INSTS_TO_INDEX.put("putnil", new Byte((byte) 15));
        INSTS_TO_INDEX.put("putself", new Byte((byte) 16));
        INSTS_TO_INDEX.put("putobject", new Byte((byte) 17));
        INSTS_TO_INDEX.put("putspecialobject", new Byte((byte) 18));
        INSTS_TO_INDEX.put("putiseq", new Byte((byte) 19));
        INSTS_TO_INDEX.put("putstring", new Byte((byte) 20));
        INSTS_TO_INDEX.put("concatstrings", new Byte((byte) 21));
        INSTS_TO_INDEX.put("tostring", new Byte((byte) 22));
        INSTS_TO_INDEX.put("toregexp", new Byte((byte) 23));
        INSTS_TO_INDEX.put("newarray", new Byte((byte) 24));
        INSTS_TO_INDEX.put("duparray", new Byte((byte) 25));
        INSTS_TO_INDEX.put("expandarray", new Byte((byte) 26));
        INSTS_TO_INDEX.put("concatarray", new Byte((byte) 27));
        INSTS_TO_INDEX.put("splatarray", new Byte((byte) 28));
        INSTS_TO_INDEX.put("checkincludearray", new Byte((byte) 29));
        INSTS_TO_INDEX.put("newhash", new Byte((byte) 30));
        INSTS_TO_INDEX.put("newrange", new Byte((byte) 31));
        INSTS_TO_INDEX.put("pop", new Byte((byte) 32));
        INSTS_TO_INDEX.put("dup", new Byte((byte) 33));
        INSTS_TO_INDEX.put("dupn", new Byte((byte) 34));
        INSTS_TO_INDEX.put("swap", new Byte((byte) 35));
        INSTS_TO_INDEX.put("reput", new Byte((byte) 36));
        INSTS_TO_INDEX.put("topn", new Byte((byte) 37));
        INSTS_TO_INDEX.put("setn", new Byte((byte) 38));
        INSTS_TO_INDEX.put("adjuststack", new Byte((byte) 39));
        INSTS_TO_INDEX.put("defined", new Byte((byte) 40));
        INSTS_TO_INDEX.put("trace", new Byte((byte) 41));
        INSTS_TO_INDEX.put("defineclass", new Byte((byte) 42));
        INSTS_TO_INDEX.put("send", new Byte((byte) 43));
        INSTS_TO_INDEX.put("invokesuper", new Byte((byte) 44));
        INSTS_TO_INDEX.put("invokeblock", new Byte((byte) 45));
        INSTS_TO_INDEX.put("leave", new Byte((byte) 46));
        INSTS_TO_INDEX.put("finish", new Byte((byte) 47));
        INSTS_TO_INDEX.put("throw", new Byte((byte) 48));
        INSTS_TO_INDEX.put("jump", new Byte((byte) 49));
        INSTS_TO_INDEX.put("branchif", new Byte((byte) 50));
        INSTS_TO_INDEX.put("branchunless", new Byte((byte) 51));
        INSTS_TO_INDEX.put("getinlinecache", new Byte((byte) 52));
        INSTS_TO_INDEX.put("onceinlinecache", new Byte((byte) 53));
        INSTS_TO_INDEX.put("setinlinecache", new Byte((byte) 54));
        INSTS_TO_INDEX.put("opt_case_dispatch", new Byte((byte) 55));
        INSTS_TO_INDEX.put("opt_checkenv", new Byte((byte) 56));
        INSTS_TO_INDEX.put("opt_plus", new Byte((byte) 57));
        INSTS_TO_INDEX.put("opt_minus", new Byte((byte) 58));
        INSTS_TO_INDEX.put("opt_mult", new Byte((byte) 59));
        INSTS_TO_INDEX.put("opt_div", new Byte((byte) 60));
        INSTS_TO_INDEX.put("opt_mod", new Byte((byte) 61));
        INSTS_TO_INDEX.put("opt_eq", new Byte((byte) 62));
        INSTS_TO_INDEX.put("opt_neq", new Byte((byte) 63));
        INSTS_TO_INDEX.put("opt_lt", new Byte((byte) 64));
        INSTS_TO_INDEX.put("opt_le", new Byte((byte) 65));
        INSTS_TO_INDEX.put("opt_gt", new Byte((byte) 66));
        INSTS_TO_INDEX.put("opt_ge", new Byte((byte) 67));
        INSTS_TO_INDEX.put("opt_ltlt", new Byte((byte) 68));
        INSTS_TO_INDEX.put("opt_aref", new Byte((byte) 69));
        INSTS_TO_INDEX.put("opt_aset", new Byte((byte) 70));
        INSTS_TO_INDEX.put("opt_length", new Byte((byte) 71));
        INSTS_TO_INDEX.put("opt_size", new Byte((byte) 72));
        INSTS_TO_INDEX.put("opt_succ", new Byte((byte) 73));
        INSTS_TO_INDEX.put("opt_not", new Byte((byte) 74));
        INSTS_TO_INDEX.put("opt_regexpmatch1", new Byte((byte) 75));
        INSTS_TO_INDEX.put("opt_regexpmatch2", new Byte((byte) 76));
        INSTS_TO_INDEX.put("opt_call_c_function", new Byte((byte) 77));
        INSTS_TO_INDEX.put("bitblt", new Byte((byte) 78));
        INSTS_TO_INDEX.put("answer", new Byte((byte) 79));
        INSTS_TO_INDEX.put("send_no_arg", new Byte((byte) 80));
        INSTS_TO_INDEX.put("send_one_arg", new Byte((byte) 81));
        INSTS_TO_INDEX.put("send_two_arg", new Byte((byte) 82));
        INSTS_TO_INDEX.put("send_three_arg", new Byte((byte) 83));
        INSTS_TO_INDEX.put("send_many_arg", new Byte((byte) 84));
        INSTS_TO_INDEX.put("send_no_arg_block", new Byte((byte) 85));
        INSTS_TO_INDEX.put("send_one_arg_block", new Byte((byte) 86));
        INSTS_TO_INDEX.put("send_two_arg_block", new Byte((byte) 87));
        INSTS_TO_INDEX.put("send_three_arg_block", new Byte((byte) 88));
        INSTS_TO_INDEX.put("send_many_arg_block", new Byte((byte) 89));
    }
    public static byte instruction(String name) {
        return ((Byte)INSTS_TO_INDEX.get(name)).byteValue();
    }

    public static final String[] INDEX_TO_NAME = new String[] { 
                      "nop", 
                      "getlocal", 
                      "setlocal", 
                      "getspecial", 
                      "setspecial", 
                      "getdynamic", 
                      "setdynamic", 
                      "getinstancevariable", 
                      "setinstancevariable", 
                      "getclassvariable", 
                      "setclassvariable", 
                      "getconstant", 
                      "setconstant", 
                      "getglobal", 
                      "setglobal", 
                      "putnil", 
                      "putself", 
                      "putobject", 
                      "putspecialobject", 
                      "putiseq", 
                      "putstring", 
                      "concatstrings", 
                      "tostring", 
                      "toregexp", 
                      "newarray", 
                      "duparray", 
                      "expandarray", 
                      "concatarray", 
                      "splatarray", 
                      "checkincludearray", 
                      "newhash", 
                      "newrange", 
                      "pop", 
                      "dup", 
                      "dupn", 
                      "swap", 
                      "reput", 
                      "topn", 
                      "setn", 
                      "adjuststack", 
                      "defined", 
                      "trace", 
                      "defineclass", 
                      "send", 
                      "invokesuper", 
                      "invokeblock", 
                      "leave", 
                      "finish", 
                      "throw", 
                      "jump", 
                      "branchif", 
                      "branchunless", 
                      "getinlinecache", 
                      "onceinlinecache", 
                      "setinlinecache", 
                      "opt_case_dispatch", 
                      "opt_checkenv", 
                      "opt_plus", 
                      "opt_minus", 
                      "opt_mult", 
                      "opt_div", 
                      "opt_mod", 
                      "opt_eq", 
                      "opt_neq", 
                      "opt_lt", 
                      "opt_le", 
                      "opt_gt", 
                      "opt_ge", 
                      "opt_ltlt", 
                      "opt_aref", 
                      "opt_aset", 
                      "opt_length", 
                      "opt_size", 
                      "opt_succ", 
                      "opt_not", 
                      "opt_regexpmatch1", 
                      "opt_regexpmatch2", 
                      "opt_call_c_function", 
                      "bitblt", 
                      "answer", 
                      "send_no_arg", 
                      "send_one_arg", 
                      "send_two_arg", 
                      "send_three_arg", 
                      "send_many_arg", 
                      "send_no_arg_block", 
                      "send_one_arg_block", 
                      "send_two_arg_block", 
                      "send_three_arg_block", 
                      "send_many_arg_block"};

    public static String name(int index) {
        return INDEX_TO_NAME[index];
    }
    
    public static final byte LAST_OPCODE = 89;

    public static final int ARGS_SPLAT_FLAG = 2;
    public static final int ARGS_BLOCKARG_FLAG = 4;
    public static final int FCALL_FLAG = 8;
    public static final int VCALL_FLAG = 16;
    public static final int TAILCALL_FLAG = 32;
    public static final int TAILRECURSION_FLAG = 64;
    public static final int SUPER_FLAG = 128;
    public static final int OPT_SEND_FLAG = 256;

    public static final byte RUBY_TAG_RETURN = 0x1;
    public static final byte RUBY_TAG_BREAK = 0x2;
    public static final byte RUBY_TAG_NEXT = 0x3;
    public static final byte RUBY_TAG_RETRY = 0x4;
    public static final byte RUBY_TAG_REDO = 0x5;
    public static final byte RUBY_TAG_RAISE = 0x6;
    public static final byte RUBY_TAG_THROW = 0x7;
    public static final byte RUBY_TAG_FATAL = 0x8;
    public static final byte RUBY_TAG_MASK = 0xf;
}
