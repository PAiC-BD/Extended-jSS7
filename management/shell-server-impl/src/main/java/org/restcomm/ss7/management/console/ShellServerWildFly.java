/*
 * TeleStax, Open Source Cloud Communications  Copyright 2012.
 * and individual contributors
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.restcomm.ss7.management.console;

import java.io.IOException;
import java.security.Principal;
import java.util.List;
import java.util.Map;

import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.jboss.security.authentication.JBossCachedAuthenticationManager;
import org.restcomm.protocols.ss7.scheduler.Scheduler;

/**
 * @author amit bhayani
 * @author sergey vetyutnev
 *
 */
public class ShellServerWildFly extends ShellServer {

    private JBossCachedAuthenticationManager jbossAuthManagement = null;

    public ShellServerWildFly(Scheduler scheduler, List<ShellExecutor> shellExecutors) throws IOException {
        super(scheduler, shellExecutors);
    }

    @Override
    protected void startSecurityManager(InitialContext initialContext, String securityDomain) throws NamingException {
        Object jaasAuthManagement = initialContext.lookup("java:jboss/jaas/" + this.getSecurityDomain());
        logger.debug("jaas Object: "+jaasAuthManagement);
        if (jaasAuthManagement != null && jaasAuthManagement instanceof JBossCachedAuthenticationManager) {
            logger.info("jaas Object: "+jaasAuthManagement.getClass());
            this.jbossAuthManagement = (JBossCachedAuthenticationManager)jaasAuthManagement;
        }
    }

    @Override
    protected void putPrincipal(Map map, Principal principal) {
        map.put("principal", principal);
    }

    @Override
    protected boolean isAuthManagementLoaded() {
        return jbossAuthManagement != null;
    }

    @Override
    protected boolean isValid(Principal principal, Object credential) {
        return this.jbossAuthManagement.isValid(principal, credential);
    }

    @Override
    protected String getLocalSecurityDomain() {
        return this.jbossAuthManagement.getSecurityDomain();
    }

}
