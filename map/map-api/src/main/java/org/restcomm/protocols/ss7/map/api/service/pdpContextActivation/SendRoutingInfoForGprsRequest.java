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

package org.restcomm.protocols.ss7.map.api.service.pdpContextActivation;

import org.restcomm.protocols.ss7.map.api.primitives.GSNAddress;
import org.restcomm.protocols.ss7.map.api.primitives.IMSI;
import org.restcomm.protocols.ss7.map.api.primitives.ISDNAddressString;
import org.restcomm.protocols.ss7.map.api.primitives.MAPExtensionContainer;

/**
 *
<code>
MAP V3-4:

sendRoutingInfoForGprs OPERATION ::= {
  --Timer m
  ARGUMENT SendRoutingInfoForGprsArg
  RESULT SendRoutingInfoForGprsRes
  ERRORS { absentSubscriber | systemFailure | dataMissing | unexpectedDataValue | unknownSubscriber | callBarred }
  CODE local:24
}

SendRoutingInfoForGprsArg ::= SEQUENCE {
  imsi                [0] IMSI,
  ggsn-Address        [1] GSN-Address OPTIONAL,
  ggsn-Number         [2] ISDN-AddressString,
  extensionContainer  [3] ExtensionContainer OPTIONAL,
  ...
}
</code>
 *
 *
 * @author sergey vetyutnev
 *
 */
public interface SendRoutingInfoForGprsRequest extends PdpContextActivationMessage {

    IMSI getImsi();

    GSNAddress getGgsnAddress();

    ISDNAddressString getGgsnNumber();

    MAPExtensionContainer getExtensionContainer();

}
