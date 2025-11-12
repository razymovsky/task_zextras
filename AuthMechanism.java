package com.zimbra.cs.account.auth;

import com.zimbra.common.service.ServiceException;
import com.zimbra.cs.account.Account;
import com.zimbra.cs.account.AccountServiceException;
import com.zimbra.cs.account.Domain;
import com.zimbra.cs.account.auth.AuthMechanism;
import com.zimbra.cs.account.auth.PasswordUtil;
import com.zimbra.cs.account.ldap.LdapProv;
import com.zimbra.cs.account.ldap.entry.LdapEntry;
import com.zimbra.cs.listeners.AuthListener;
import java.util.Map;

/* loaded from: AuthMechanism$ZimbraAuth.class */
public class AuthMechanism$ZimbraAuth extends AuthMechanism {
    AuthMechanism$ZimbraAuth(AuthMechanism.AuthMech authMech) {
        super(authMech);
    }

    protected boolean isEncodedPassword(String encodedPassword) {
        return PasswordUtil.SSHA512.isSSHA512(encodedPassword) || PasswordUtil.SSHA.isSSHA(encodedPassword);
    }

    protected boolean isValidEncodedPassword(String encodedPassword, String password) {
        return PasswordUtil.SSHA512.verifySSHA512(encodedPassword, password) || PasswordUtil.SSHA.verifySSHA(encodedPassword, password);
    }

    public boolean isZimbraAuth() {
        return true;
    }

    /* JADX INFO: Thrown type has an unknown type hierarchy: com.zimbra.cs.account.AccountServiceException$AuthFailedServiceException */
    public void doAuth(LdapProv prov, Domain domain, Account acct, String password, Map<String, Object> authCtxt) throws AccountServiceException.AuthFailedServiceException, ServiceException {
        if (AuthMechanism.doTwoFactorAuth(acct, password, authCtxt)) {
            return;
        }
        String encodedPassword = acct.getAttr("userPassword");
        if (encodedPassword == null) {
            AccountServiceException.AuthFailedServiceException afse = AccountServiceException.AuthFailedServiceException.AUTH_FAILED(acct.getName(), namePassedIn(authCtxt), "missing userPassword");
            AuthListener.invokeOnException(afse);
            throw afse;
        }
        if (isEncodedPassword(encodedPassword)) {
            if (isValidEncodedPassword(encodedPassword, password)) {
                return;
            }
            acct.refreshUserCredentials();
            String refreshedPassword = acct.getAttr("userPassword");
            if (!isEncodedPassword(refreshedPassword)) {
                doAuth(prov, domain, acct, password, authCtxt);
            }
            if (!isValidEncodedPassword(encodedPassword, refreshedPassword)) {
                AccountServiceException.AuthFailedServiceException afe = AccountServiceException.AuthFailedServiceException.AUTH_FAILED(acct.getName(), namePassedIn(authCtxt), "invalid password");
                AuthListener.invokeOnException(afe);
                throw afe;
            }
            return;
        }
        if (acct instanceof LdapEntry) {
            prov.zimbraLdapAuthenticate(acct, password, authCtxt);
        } else {
            AccountServiceException.AuthFailedServiceException afse2 = AccountServiceException.AuthFailedServiceException.AUTH_FAILED(acct.getName(), namePassedIn(authCtxt));
            AuthListener.invokeOnException(afse2);
            throw afse2;
        }
    }

    public boolean checkPasswordAging() throws ServiceException {
        return true;
    }
}