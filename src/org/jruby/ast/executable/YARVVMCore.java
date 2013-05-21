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

import org.jruby.MetaClass;
import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyFixnum;
import org.jruby.RubyModule;
import org.jruby.RubyObject;
import org.jruby.RubySymbol;
import org.jruby.anno.JRubyMethod;
import org.jruby.common.IRubyWarnings.ID;
import org.jruby.internal.runtime.methods.WrapperMethod;
import org.jruby.internal.runtime.methods.YARVMethod;
import org.jruby.parser.StaticScope;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.builtin.IRubyObject;

/**
 * @author betasheet
 */
public class YARVVMCore extends RubyObject {

    public YARVVMCore(Ruby runtime, RubyClass cls) {
        super(runtime, cls);
    }

    public static RubyClass createYARVVMCore(Ruby runtime) {
        RubyClass vmCoreClass = runtime.defineClass("YARVVMCore", runtime.getClass("Object"),
                ObjectAllocator.NOT_ALLOCATABLE_ALLOCATOR);

        vmCoreClass.defineAnnotatedMethods(YARVVMCore.class);
        return vmCoreClass;
    }

    @JRubyMethod(meta = true, name = "core#set_method_alias")
    public static IRubyObject coreSetMethodAlias(ThreadContext context, IRubyObject recv,
            IRubyObject arg0, IRubyObject arg1, IRubyObject arg2) {
        // VALUE cbase, VALUE sym1, VALUE sym2

        System.out.println("unimplemented: core#set_method_alias");
        // TODO unimplemented
        return context.nil;
    }

    @JRubyMethod(meta = true, name = "core#set_variable_alias")
    public static IRubyObject coreSetVariableAlias(ThreadContext context, IRubyObject recv,
            IRubyObject arg0, IRubyObject arg1) {
        // VALUE sym1, VALUE sym2

        System.out.println("unimplemented: core#set_variable_alias");
        // TODO unimplemented
        return context.nil;
    }

    @JRubyMethod(meta = true, name = "core#undef_method")
    public static IRubyObject coreUndefMethod(ThreadContext context, IRubyObject recv,
            IRubyObject arg0, IRubyObject arg1) {
        // VALUE cbase, VALUE sym

        System.out.println("unimplemented: core#undef_method");
        // TODO unimplemented
        return context.nil;
    }

    @JRubyMethod(meta = true, name = "core#define_method")
    public static IRubyObject coreDefineMethod(ThreadContext context, IRubyObject recv,
            IRubyObject arg0, IRubyObject arg1, IRubyObject arg2) {
        // VALUE cbase, VALUE sym, VALUE iseqval

        Ruby runtime = context.getRuntime();
        
        RubyModule containingClass = (RubyModule) arg0;
        String mname = ((RubySymbol) arg1).asJavaString();
        YARVByteCode byteCode = ((YARVByteCode) arg2);

        if (containingClass == null) {
            throw runtime.newTypeError("No class to add method.");
        }

        if (containingClass == runtime.getObject() && mname == "initialize") {
            runtime.getWarnings().warn(ID.REDEFINING_DANGEROUS,
                    "redefining Object#initialize may cause infinite loop");
        }

        Visibility visibility = context.getCurrentVisibility();
        if (mname == "initialize" || visibility == Visibility.MODULE_FUNCTION) {
            visibility = Visibility.PRIVATE;
        }

        if (containingClass.isSingleton()) {
            IRubyObject attachedObject = ((MetaClass) containingClass).getAttached();

            if (attachedObject instanceof RubyFixnum || attachedObject instanceof RubySymbol) {
                throw runtime.newTypeError("can't define singleton method \"" + mname + "\" for "
                        + attachedObject.getType());
            }
        }
        
        StaticScope sco = runtime.getStaticScopeFactory().newLocalScope(context.getCurrentStaticScope());
        sco.setVariables(byteCode.locals);
        sco.determineModule();
        
        YARVMethod newMethod = new YARVMethod(containingClass, byteCode, sco,
                visibility);

        containingClass.addMethod(mname, newMethod);

        if (context.getCurrentVisibility() == Visibility.MODULE_FUNCTION) {
            RubyModule singleton = containingClass.getSingletonClass();
            singleton.addMethod(mname, new WrapperMethod(singleton, newMethod, Visibility.PUBLIC));
            containingClass.callMethod(context, "singleton_method_added",
                    runtime.fastNewSymbol(mname));
        }

        // 'class << state.self' and 'class << obj' uses defn as opposed to defs
        if (containingClass.isSingleton()) {
            ((MetaClass) containingClass).getAttached().callMethod(context,
                    "singleton_method_added", runtime.fastNewSymbol(mname));
        } else {
            containingClass.callMethod(context, "method_added", runtime.fastNewSymbol(mname));
        }

        runtime.incGlobalState();

        return context.nil;
    }

    @JRubyMethod(meta = true, name = "core#define_singleton_method")
    public static IRubyObject coreDefineSingletonMethod(ThreadContext context, IRubyObject recv,
            IRubyObject arg0, IRubyObject arg1, IRubyObject arg2) {
        // VALUE cbase, VALUE sym, VALUE iseqval

        System.out.println("unimplemented: core#define_singleton_method");
        // TODO unimplemented
        return context.nil;
    }

    @JRubyMethod(meta = true, name = "core#set_postexe")
    public static IRubyObject coreSetPostexe(ThreadContext context, IRubyObject recv,
            IRubyObject arg0) {
        // VALUE iseqval

        System.out.println("unimplemented: core#set_postexe");
        // TODO unimplemented
        return context.nil;
    }

}
