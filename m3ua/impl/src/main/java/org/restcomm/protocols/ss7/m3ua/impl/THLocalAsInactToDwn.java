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
import org.restcomm.protocols.ss7.m3ua.Asp;
import org.restcomm.protocols.ss7.m3ua.impl.fsm.FSM;
import org.restcomm.protocols.ss7.m3ua.impl.fsm.FSMState;
import org.restcomm.protocols.ss7.m3ua.impl.fsm.TransitionHandler;

/**
 *
 * @author amit bhayani
 *
 */
public class THLocalAsInactToDwn implements TransitionHandler {

    private static final Logger logger = Logger.getLogger(THLocalAsInactToDwn.class);

    private AsImpl asImpl = null;
    private FSM fsm;

    public THLocalAsInactToDwn(AsImpl asImpl, FSM fsm) {
        this.asImpl = asImpl;
        this.fsm = fsm;
    }

    int inactCount = 0;

    public boolean process(FSMState state) {
        inactCount = 0;

        try {
            for (FastList.Node<Asp> n = this.asImpl.appServerProcs.head(), end = this.asImpl.appServerProcs.tail(); (n = n
                    .getNext()) != end;) {
                AspImpl remAspImpl = (AspImpl) n.getValue();

                FSM aspPeerFSM = remAspImpl.getPeerFSM();
                AspState aspState = AspState.getState(aspPeerFSM.getState().getName());

                if (aspState == AspState.INACTIVE) {
                    inactCount++;
                }
            }

            if (inactCount > 0) {
                // We have atleast one more ASP in INACTIVE state, the AS should
                // remain INACTIVE
                return false;
            }

            return true;
        } catch (Exception e) {
            logger.error(String.format("Error while translating Rem AS to DOWN. %s", this.fsm.toString()), e);
        }
        // something wrong
        return false;

    }
}
