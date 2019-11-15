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

import org.restcomm.protocols.ss7.map.api.primitives.FTNAddressString;
import org.restcomm.protocols.ss7.map.api.primitives.ISDNAddressString;
import org.restcomm.protocols.ss7.map.api.primitives.ISDNSubaddressString;
import org.restcomm.protocols.ss7.map.api.primitives.MAPExtensionContainer;

/**
 *
 Ext-ForwFeature ::= SEQUENCE { basicService Ext-BasicServiceCode OPTIONAL, ss-Status [4] Ext-SS-Status, forwardedToNumber [5]
 * ISDN-AddressString OPTIONAL, -- When this data type is sent from an HLR which supports CAMEL Phase 2 -- to a VLR that
 * supports CAMEL Phase 2 the VLR shall not check the -- format of the number forwardedToSubaddress [8] ISDN-SubaddressString
 * OPTIONAL, forwardingOptions [6] Ext-ForwOptions OPTIONAL, noReplyConditionTime [7] Ext-NoRepCondTime OPTIONAL,
 * extensionContainer [9] ExtensionContainer OPTIONAL, ..., longForwardedToNumber [10] FTN-AddressString OPTIONAL }
 *
 * Ext-NoRepCondTime ::= INTEGER (1..100) -- Only values 5-30 are used. -- Values in the ranges 1-4 and 31-100 are reserved for
 * future use -- If received: -- values 1-4 shall be mapped on to value 5 -- values 31-100 shall be mapped on to value 30
 *
 *
 *
 * @author sergey vetyutnev
 *
 */
public interface ExtForwFeature extends Serializable {

    ExtBasicServiceCode getBasicService();

    ExtSSStatus getSsStatus();

    ISDNAddressString getForwardedToNumber();

    ISDNSubaddressString getForwardedToSubaddress();

    ExtForwOptions getForwardingOptions();

    Integer getNoReplyConditionTime();

    MAPExtensionContainer getExtensionContainer();

    FTNAddressString getLongForwardedToNumber();

}
