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

package org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement;

import java.io.Serializable;
import java.util.ArrayList;

import org.restcomm.protocols.ss7.map.api.primitives.MAPExtensionContainer;

/**
 *
 O-CSI ::= SEQUENCE { o-BcsmCamelTDPDataList O-BcsmCamelTDPDataList, extensionContainer ExtensionContainer OPTIONAL, ...,
 * camelCapabilityHandling [0] CamelCapabilityHandling OPTIONAL, notificationToCSE [1] NULL OPTIONAL, csiActive [2] NULL
 * OPTIONAL} -- notificationtoCSE and csiActive shall not be present when O-CSI is sent to VLR/GMSC. -- They may only be
 * included in ATSI/ATM ack/NSDC message. -- O-CSI shall not be segmented.
 *
 * O-BcsmCamelTDPDataList ::= SEQUENCE SIZE (1..10) OF O-BcsmCamelTDPData -- O-BcsmCamelTDPDataList shall not contain more than
 * one instance of -- O-BcsmCamelTDPData containing the same value for o-BcsmTriggerDetectionPoint. -- For CAMEL Phase 2, this
 * means that only one instance of O-BcsmCamelTDPData is allowed -- with o-BcsmTriggerDetectionPoint being equal to DP2.
 *
 * CamelCapabilityHandling ::= INTEGER(1..16) -- value 1 = CAMEL phase 1, -- value 2 = CAMEL phase 2, -- value 3 = CAMEL Phase
 * 3, -- value 4 = CAMEL phase 4: -- reception of values greater than 4 shall be treated as CAMEL phase 4.
 *
 *
 *
 * @author sergey vetyutnev
 *
 */
public interface OCSI extends Serializable {

    ArrayList<OBcsmCamelTDPData> getOBcsmCamelTDPDataList();

    MAPExtensionContainer getExtensionContainer();

    Integer getCamelCapabilityHandling();

    boolean getNotificationToCSE();

    boolean getCsiActive();

}
