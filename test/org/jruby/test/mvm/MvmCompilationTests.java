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
package org.jruby.test.mvm;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.Charset;

import org.jruby.Ruby;
import org.jruby.RubyIO;
import org.jruby.RubyInstanceConfig;
import org.jruby.test.TestRubyBase;

/**
 * @author betasheet
 */
public class MvmCompilationTests extends TestRubyBase {

    public void testBinarytrees() throws Exception {
        evalFile("mvm/testscripts/binarytrees.rb", new String[] { "12" },
                "mvm/testscripts/expectedOutputs/binarytrees.rb.log");
    }

    public void evalFile(String fileName, String[] params, String expectedOutputFileName)
            throws Exception {
        RubyInstanceConfig cfg = new RubyInstanceConfig();
        cfg.setArgv(params);
        runtime = Ruby.newInstance(cfg);

        String contents = readFile(fileName);
        String expectedOutput = readFile(expectedOutputFileName);
        String output = eval(contents);
        
        StringBuffer sb = new StringBuffer(expectedOutput.trim());
        for (int idx = sb.indexOf("\n"); idx != -1; idx = sb.indexOf("\n")) {
            sb.deleteCharAt(idx);
        }
        
        assertEquals(sb.toString(), output.trim());
    }

    private static String readFile(String path) throws IOException {
        FileInputStream stream = new FileInputStream(new File(path));
        try {
            FileChannel fc = stream.getChannel();
            MappedByteBuffer bb = fc.map(FileChannel.MapMode.READ_ONLY, 0, fc.size());
            /* Instead of using default, pass in a decoder. */
            return Charset.defaultCharset().decode(bb).toString();
        } finally {
            stream.close();
        }
    }

}
