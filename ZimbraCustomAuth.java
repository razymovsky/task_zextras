package com.zimbra.cs.account.auth;

import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/* loaded from: ZimbraCustomAuth.class */
public abstract class ZimbraCustomAuth {
    private static Map<String, ZimbraCustomAuth> mHandlers;

    public abstract void authenticate(Account account, String str, Map<String, Object> map, List<String> list) throws Exception;

    static {
        register("hosted", new HostedAuth());
    }

    public static synchronized void register(String handlerName, ZimbraCustomAuth handler) {
        if (mHandlers == null) {
            mHandlers = new HashMap();
        } else {
            ZimbraCustomAuth obj = mHandlers.get(handlerName);
            if (obj != null) {
                ZimbraLog.account.warn("handler name " + handlerName + " is already registered, registering of " + obj.getClass().getCanonicalName() + " is ignored");
                return;
            }
        }
        mHandlers.put(handlerName, handler);
    }

    public static synchronized ZimbraCustomAuth getHandler(String handlerName) {
        if (mHandlers == null) {
            return null;
        }
        return mHandlers.get(handlerName);
    }

    public boolean checkPasswordAging() {
        return false;
    }
}