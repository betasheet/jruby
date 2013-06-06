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

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyObject;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.YARVBlockBody;
import org.jruby.runtime.builtin.IRubyObject;

import com.sun.max.vm.compiler.target.TargetMethod;

/**
 * @author betasheet
 */
public class YARVByteCode extends RubyObject {

    public class InlineCache {
        public long state;
        public Object cachedObject;

        public void update(long state, IRubyObject cachedObject) {
            this.cachedObject = cachedObject;
            this.state = state;
        }
        
        public Object get(long state) {
            return (this.state == state) ? cachedObject : null;
        }
    }

    private static Object[] constants = new Object[8192];
    private static int constantCounter;

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

    public ByteArrayOutputStream bodyBuffer = new ByteArrayOutputStream(256);
    public DataOutputStream bodyBufferStream = new DataOutputStream(bodyBuffer);
    public byte[] body;
    public int instructionCount;

    public TargetMethod targetMethod;
    public YARVBlockBody blockBody;

    private InlineCache[] inlineCaches = new InlineCache[1024];

    public YARVByteCode(Ruby runtime, RubyClass metaClass) {
        super(runtime, metaClass);
    }

    YARVByteCode() {
        super(Ruby.getGlobalRuntime(), null);
    }

    public int getOptArgsLength() {
        return args_opt_labels == null ? 0 : args_opt_labels.length;
    }

    public InlineCache getInlineCache(int id) {
        InlineCache ic = inlineCaches[id];
        if (ic == null)
            ic = new InlineCache();
        inlineCaches[id] = ic;
        return ic;
    }

    public static RubyClass createYARVByteCode(Ruby runtime) {
        RubyClass iseq = runtime.defineClass("YARVByteCode", runtime.getClass("Data"),
                ObjectAllocator.NOT_ALLOCATABLE_ALLOCATOR);

        iseq.defineAnnotatedMethods(YARVByteCode.class);

        return iseq;
    }

    public int getNextInstructionPosition() {
        return bodyBuffer.size();
    }

    public int pushInstruction(byte instruction) {
        int pos = bodyBuffer.size();
        bodyBuffer.write(instruction);
        instructionCount++;
        return pos;
    }

    public void closeBuffer() {
        body = bodyBuffer.toByteArray();
        bodyBuffer = null;
    }

    public void push(int val) {
        try {
            bodyBufferStream.writeInt(val);
        } catch (IOException e) {
        }
    }

    public void push(long val) {
        try {
            bodyBufferStream.writeLong(val);
        } catch (IOException e) {
        }
    }

    public void push(Object val) {
        push(addConstant(val));
    }

    private static int addConstant(Object val) {
        constants[constantCounter] = val;
        return constantCounter++;
    }

    public static Object getConstant(int id) {
        return constants[id];
    }

    public static Object getConstant(byte[] body, int pos) {
        return constants[getInt(body, pos)];
    }

    public static int getInt(byte[] body, int pos) {
        return (body[pos] << 24) + ((body[pos + 1] & 0xff) << 16) + ((body[pos + 2] & 0xff) << 8)
                + (body[pos + 3] & 0xff);
    }

    public static long getLong(byte[] body, int pos) {
        return ((long) body[pos] << 56) + (((long) body[pos + 1] & 0xff) << 48)
                + (((long) body[pos + 1] & 0xff) << 40) + (((long) body[pos + 1] & 0xff) << 32)
                + (((long) body[pos + 1] & 0xff) << 24) + (((long) body[pos + 1] & 0xff) << 16)
                + (((long) body[pos + 2] & 0xff) << 8) + ((long) body[pos + 3] & 0xff);
    }

    public void setJumpTarget(int instructionPos, int targetPos) {
        setInt(instructionPos + 1, targetPos);
    }

    public void setInt(int pos, int val) {
        body[pos] = (byte) ((val >>> 24) & 0xFF);
        body[pos + 1] = (byte) ((val >>> 16) & 0xFF);
        body[pos + 2] = (byte) ((val >>> 8) & 0xFF);
        body[pos + 3] = (byte) ((val >>> 0) & 0xFF);
    }

    public void setLong(int pos, int val) {
        body[pos] = (byte) ((val >>> 56) & 0xFF);
        body[pos + 1] = (byte) ((val >>> 48) & 0xFF);
        body[pos + 2] = (byte) ((val >>> 40) & 0xFF);
        body[pos + 3] = (byte) ((val >>> 32) & 0xFF);
        body[pos + 4] = (byte) ((val >>> 24) & 0xFF);
        body[pos + 5] = (byte) ((val >>> 16) & 0xFF);
        body[pos + 6] = (byte) ((val >>> 8) & 0xFF);
        body[pos + 7] = (byte) ((val >>> 0) & 0xFF);
    }
}
