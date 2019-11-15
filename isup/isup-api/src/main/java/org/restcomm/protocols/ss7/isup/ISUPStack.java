/*
 * TeleStax, Open Source Cloud Communications
 * Copyright 2012, Telestax Inc and individual contributors
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

/**
 * Start time:09:07:18 2009-08-30<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 */
package org.restcomm.protocols.ss7.isup;

import org.restcomm.protocols.ss7.mtp.Mtp3UserPart;

/**
 * Start time:09:07:18 2009-08-30<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author baranowb
 */
public interface ISUPStack {

    /**
     * Get instance of provider.
     *
     * @return
     */
    ISUPProvider getIsupProvider();

    /**
     * Stop stack and all underlying resources.
     */
    void stop();

    /**
     * Start stack and all underlying resources
     *
     * @throws IllegalStateException - if stack is already running or is not configured yet.
     * @throws StartFailedException - if start failed for some other reason.
     */
    void start() throws IllegalStateException;

    Mtp3UserPart getMtp3UserPart();

    void setMtp3UserPart(Mtp3UserPart mtp3UserPart);

    void setCircuitManager(CircuitManager mgr);

    CircuitManager getCircuitManager();
}
