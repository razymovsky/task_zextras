package com.zimbra.cs.account.auth;

import com.zimbra.common.service.ServiceException;

/* loaded from: AuthMechanism$AuthMech.class */
public enum AuthMechanism$AuthMech {
    zimbra,
    ldap,
    ad,
    kerberos5,
    custom;

    /* JADX INFO: Thrown type has an unknown type hierarchy: com.zimbra.common.service.ServiceException */
    public static AuthMechanism$AuthMech fromString(String authMechStr) throws ServiceException {
        if (authMechStr == null) {
            return null;
        }
        try {
            return valueOf(authMechStr);
        } catch (IllegalArgumentException e) {
            throw ServiceException.INVALID_REQUEST("unknown auth mech: " + authMechStr, e);
        }
    }
}