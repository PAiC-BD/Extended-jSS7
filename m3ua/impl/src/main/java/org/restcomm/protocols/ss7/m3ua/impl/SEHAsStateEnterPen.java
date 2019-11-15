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
package org.restcomm.protocols.ss7.m3ua.impl;

import javolution.util.FastList;

import org.apache.log4j.Logger;
import org.restcomm.protocols.ss7.m3ua.M3UAManagementEventListener;
import org.restcomm.protocols.ss7.m3ua.State;
import org.restcomm.protocols.ss7.m3ua.impl.fsm.FSM;
import org.restcomm.protocols.ss7.m3ua.impl.fsm.FSMState;
import org.restcomm.protocols.ss7.m3ua.impl.fsm.FSMStateEventHandler;

/**
 *
 * @author amit bhayani
 *
 */
public abstract class SEHAsStateEnterPen implements FSMStateEventHandler {

    private static final Logger logger = Logger.getLogger(SEHAsStateEnterPen.class);

    protected AsImpl asImpl = null;
    private FSM fsm;

    public SEHAsStateEnterPen(AsImpl asImpl, FSM fsm) {
        this.asImpl = asImpl;
        this.fsm = fsm;
    }

    public void onEvent(FSMState state) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("Entered in PENDING state for As=%s", asImpl.getName()));
        }

        if (!this.asImpl.state.getName().equals(State.STATE_PENDING)) {
            AsState oldState = AsState.getState(this.asImpl.state.getName());
            this.asImpl.state = AsState.PENDING;

            FastList<M3UAManagementEventListener> managementEventListenersTmp = this.asImpl.m3UAManagementImpl.managementEventListeners;

            for (FastList.Node<M3UAManagementEventListener> n = managementEventListenersTmp.head(), end = managementEventListenersTmp
                    .tail(); (n = n.getNext()) != end;) {
                M3UAManagementEventListener m3uaManagementEventListener = n.getValue();
                try {
                    m3uaManagementEventListener.onAsPending(this.asImpl, oldState);
                } catch (Throwable ee) {
                    logger.error("Exception while invoking onAsPending", ee);
                }
            }
        }
    }
}
