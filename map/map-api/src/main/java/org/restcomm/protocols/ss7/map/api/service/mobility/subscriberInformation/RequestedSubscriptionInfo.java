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

package org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation;

import java.io.Serializable;

import org.restcomm.protocols.ss7.map.api.primitives.MAPExtensionContainer;
import org.restcomm.protocols.ss7.map.api.service.supplementary.SSForBSCode;

/**
 *
<code>
RequestedSubscriptionInfo ::= SEQUENCE {
  requestedSS-Info                 [1] SS-ForBS-Code OPTIONAL,
  odb                              [2] NULL OPTIONAL,
  requestedCAMEL-SubscriptionInfo  [3] RequestedCAMEL-SubscriptionInfo OPTIONAL,
  supportedVLR-CAMEL-Phases        [4] NULL OPTIONAL,
  supportedSGSN-CAMEL-Phases       [5] NULL OPTIONAL,
  extensionContainer               [6] ExtensionContainer OPTIONAL,
  ...,
  additionalRequestedCAMEL-SubscriptionInfo [7] AdditionalRequestedCAMEL-SubscriptionInfo OPTIONAL,
  msisdn-BS-List                            [8] NULL OPTIONAL,
  csg-SubscriptionDataRequested             [9] NULL OPTIONAL,
  cw-Info                                   [10] NULL OPTIONAL,
  clip-Info                                 [11] NULL OPTIONAL,
  clir-Info                                 [12] NULL OPTIONAL,
  hold-Info                                 [13] NULL OPTIONAL,
  ect-Info                                  [14] NULL OPTIONAL
}
</code>
 *
 *
 * @author sergey vetyutnev
 *
 */
public interface RequestedSubscriptionInfo extends Serializable {

    SSForBSCode getRequestedSSInfo();

    boolean getOdb();

    RequestedCAMELSubscriptionInfo getRequestedCAMELSubscriptionInfo();

    boolean getSupportedVlrCamelPhases();

    boolean getSupportedSgsnCamelPhases();

    MAPExtensionContainer getExtensionContainer();

    AdditionalRequestedCAMELSubscriptionInfo getAdditionalRequestedCamelSubscriptionInfo();

    boolean getMsisdnBsList();

    boolean getCsgSubscriptionDataRequested();

    boolean getCwInfo();

    boolean getClipInfo();

    boolean getClirInfo();

    boolean getHoldInfo();

    boolean getEctInfo();

}
