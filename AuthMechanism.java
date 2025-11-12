package com.zimbra.cs.account.auth;

import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.QuotedStringParser;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
import com.zimbra.cs.account.AccountServiceException;
import com.zimbra.cs.account.Domain;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.account.auth.AuthContext;
import com.zimbra.cs.account.auth.twofactor.AppSpecificPasswords;
import com.zimbra.cs.account.auth.twofactor.TwoFactorAuth;
import com.zimbra.cs.account.ldap.LdapProv;
import com.zimbra.cs.listeners.AuthListener;
import java.util.List;
import java.util.Map;

/* loaded from: AuthMechanism.class */
public abstract class AuthMechanism {
    protected AuthMech authMech;

    public abstract boolean checkPasswordAging() throws ServiceException;

    public abstract void doAuth(LdapProv ldapProv, Domain domain, Account account, String str, Map<String, Object> map) throws ServiceException;

    protected AuthMechanism(AuthMech authMech) {
        this.authMech = authMech;
    }

    public static AuthMechanism newInstance(Account acct, Map<String, Object> context) throws ServiceException {
        AuthMech authMech;
        String am;
        String authMechStr = AuthMech.zimbra.name();
        if (!acct.isIsExternalVirtualAccount()) {
            Provisioning prov = Provisioning.getInstance();
            Domain domain = prov.getDomain(acct);
            if (domain != null) {
                Boolean asAdmin = context == null ? null : (Boolean) context.get("asAdmin");
                if (asAdmin != null && asAdmin.booleanValue()) {
                    am = domain.getAuthMechAdmin();
                    if (am == null) {
                        am = domain.getAuthMech();
                    }
                } else {
                    am = domain.getAuthMech();
                }
                if (am != null) {
                    authMechStr = am;
                }
            }
        }
        if (authMechStr.startsWith(AuthMech.custom.name() + ":")) {
            return new CustomAuth(AuthMech.custom, authMechStr);
        }
        try {
            authMech = AuthMech.fromString(authMechStr);
        } catch (ServiceException e) {
            ZimbraLog.account.warn("invalid auth mech", e);
        }
        switch (1.$SwitchMap$com$zimbra$cs$account$auth$AuthMechanism$AuthMech[authMech.ordinal()]) {
            case 1:
                return new ZimbraAuth(authMech);
            case 2:
            case 3:
                return new LdapAuth(authMech);
            case 4:
                return new Kerberos5Auth(authMech);
            default:
                ZimbraLog.account.warn("unknown value for zimbraAuthMech: " + authMechStr + ", falling back to default mech");
                return new ZimbraAuth(AuthMech.zimbra);
        }
    }

    public static void doZimbraAuth(LdapProv prov, Domain domain, Account acct, String password, Map<String, Object> authCtxt) throws ServiceException {
        ZimbraAuth zimbraAuth = new ZimbraAuth(AuthMech.zimbra);
        zimbraAuth.doAuth(prov, domain, acct, password, authCtxt);
    }

    public boolean isZimbraAuth() {
        return false;
    }

    public AuthMech getMechanism() {
        return this.authMech;
    }

    public static String namePassedIn(Map<String, Object> authCtxt) {
        String npi;
        if (authCtxt != null) {
            npi = (String) authCtxt.get("anp");
            if (npi == null) {
                npi = "";
            }
        } else {
            npi = "";
        }
        return npi;
    }

    /* JADX INFO: Thrown type has an unknown type hierarchy: com.zimbra.cs.account.AccountServiceException$AuthFailedServiceException */
    public static boolean doTwoFactorAuth(Account acct, String password, Map<String, Object> authCtxt) throws AccountServiceException.AuthFailedServiceException, ServiceException {
        TwoFactorAuth twoFactorManager = TwoFactorAuth.getFactory().getTwoFactorAuth(acct);
        AppSpecificPasswords appPasswords = TwoFactorAuth.getFactory().getAppSpecificPasswords(acct);
        boolean authDone = false;
        if (twoFactorManager.twoFactorAuthRequired() && authCtxt != null) {
            AuthContext.Protocol proto = (AuthContext.Protocol) authCtxt.get("proto");
            switch (1.$SwitchMap$com$zimbra$cs$account$auth$AuthContext$Protocol[proto.ordinal()]) {
                case 1:
                case 2:
                    break;
                default:
                    if (appPasswords.isEnabled()) {
                        appPasswords.authenticate(password);
                        authDone = true;
                        break;
                    } else {
                        AccountServiceException.AuthFailedServiceException afe = AccountServiceException.AuthFailedServiceException.AUTH_FAILED(acct.getName(), namePassedIn(authCtxt), "invalid password");
                        AuthListener.invokeOnException(afe);
                        throw afe;
                    }
            }
        }
        return authDone;
    }

    public static void main(String[] args) {
        QuotedStringParser parser = new QuotedStringParser("http://blah.com:123    green \" ocean blue   \"  \"\" yelllow \"\"");
        List<String> tokens = parser.parse();
        int i = 0;
        for (String s : tokens) {
            i++;
            System.out.format("%d [%s]\n", Integer.valueOf(i), s);
        }
        new CustomAuth(AuthMech.custom, "custom:sample http://blah.com:123    green \" ocean blue   \"  \"\" yelllow \"\"");
    }
}