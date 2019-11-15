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

package org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement;

import org.restcomm.protocols.ss7.map.api.primitives.IMSI;
import org.restcomm.protocols.ss7.map.api.primitives.ISDNAddressString;
import org.restcomm.protocols.ss7.map.api.primitives.MAPExtensionContainer;
import org.restcomm.protocols.ss7.map.api.service.mobility.MobilityMessage;

/**
 *
MAP V2-3:

MAP V3: purgeMS OPERATION ::= {
--Timer m
ARGUMENT PurgeMS-Arg RESULT
  PurgeMS-Res  -- optional
  ERRORS { dataMissing | unexpectedDataValue| unknownSubscriber}
CODE local:67 }

MAP V2: PurgeMS ::= OPERATION
--Timer m
ARGUMENT purgeMS-Arg PurgeMS-Arg
RESULT

MAP V3: PurgeMS-Arg ::= [3] SEQUENCE {
  imsi         IMSI,
  vlr-Number   [0] ISDN-AddressString OPTIONAL,
  sgsn-Number  [1] ISDN-AddressString OPTIONAL,
  extensionContainer ExtensionContainer OPTIONAL,
  ...
}

MAP V2: PurgeMS-Arg ::= SEQUENCE {
  imsi         IMSI,
  vlr-Number   ISDN-AddressString,
  ...
}

 *
 * @author sergey vetyutnev
 *
 */
public interface PurgeMSRequest extends MobilityMessage {

    IMSI getImsi();

    ISDNAddressString getVlrNumber();

    ISDNAddressString getSgsnNumber();

    MAPExtensionContainer getExtensionContainer();

}
