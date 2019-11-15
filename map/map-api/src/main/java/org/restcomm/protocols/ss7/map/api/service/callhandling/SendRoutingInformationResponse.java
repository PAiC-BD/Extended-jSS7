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

package org.restcomm.protocols.ss7.map.api.service.callhandling;

import java.util.ArrayList;

import org.restcomm.protocols.ss7.map.api.primitives.ExternalSignalInfo;
import org.restcomm.protocols.ss7.map.api.primitives.IMSI;
import org.restcomm.protocols.ss7.map.api.primitives.ISDNAddressString;
import org.restcomm.protocols.ss7.map.api.primitives.MAPExtensionContainer;
import org.restcomm.protocols.ss7.map.api.primitives.NAEAPreferredCI;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.NumberPortabilityStatus;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.SubscriberInfo;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtBasicServiceCode;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.OfferedCamel4CSIs;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.SupportedCamelPhases;
import org.restcomm.protocols.ss7.map.api.service.supplementary.SSCode;

/*
<code>
MAP V3:
SendRoutingInfoRes ::= [3] SEQUENCE {
  imsi                   [9] IMSI OPTIONAL,
  extendedRoutingInfo    ExtendedRoutingInfo OPTIONAL,
  cug-CheckInfo          [3] CUG-CheckInfo OPTIONAL,
  cugSubscriptionFlag    [6] NULL OPTIONAL,
  subscriberInfo         [7] SubscriberInfo OPTIONAL,
  ss-List                [1] SS-List OPTIONAL,
  basicService           [5] Ext-BasicServiceCode OPTIONAL,
  forwardingInterrogationRequired [4] NULL OPTIONAL,
  vmsc-Address           [2] ISDN-AddressString OPTIONAL,
  extensionContainer     [0] ExtensionContainer OPTIONAL,
  ...,
  naea-PreferredCI       [10] NAEA-PreferredCI OPTIONAL,
  ccbs-Indicators        [11] CCBS-Indicators OPTIONAL,
  msisdn                     [12] ISDN-AddressString OPTIONAL,
  numberPortabilityStatus    [13] NumberPortabilityStatus OPTIONAL,
  istAlertTimer              [14] IST-AlertTimerValue OPTIONAL,
  supportedCamelPhasesInVMSC [15] SupportedCamelPhases OPTIONAL,
  offeredCamel4CSIsInVMSC    [16] OfferedCamel4CSIs OPTIONAL,
  routingInfo2               [17] RoutingInfo OPTIONAL,
  ss-List2                   [18] SS-List OPTIONAL,
  basicService2              [19] Ext-BasicServiceCode OPTIONAL,
  allowedServices            [20] AllowedServices OPTIONAL,
  unavailabilityCause        [21] UnavailabilityCause OPTIONAL,
  releaseResourcesSupported  [22] NULL OPTIONAL,
  gsm-BearerCapability       [23] ExternalSignalInfo OPTIONAL
}

MAP V2:
SendRoutingInfoRes ::= SEQUENCE {
  imsi           IMSI,
  routingInfo    RoutingInfo,
  cug-CheckInfo  CUG-CheckInfo OPTIONAL,
  -- cug-CheckInfo must be absent in version 1
  ...
}

SS-List ::= SEQUENCE SIZE (1..30) OF SS-Code

IST-AlertTimerValue ::= INTEGER (15..255)
</code>

 *
 * @author cristian veliscu
 *
 */
public interface SendRoutingInformationResponse extends CallHandlingMessage {
    IMSI getIMSI(); // TBCD-STRING

    // This is used for MAP V3 only
    ExtendedRoutingInfo getExtendedRoutingInfo(); // CHOICE

    CUGCheckInfo getCUGCheckInfo(); // SEQUENCE

    boolean getCUGSubscriptionFlag(); // NULL

    SubscriberInfo getSubscriberInfo(); // SEQUENCE

    ArrayList<SSCode> getSSList(); // SEQUENCE

    ExtBasicServiceCode getBasicService(); // CHOICE

    boolean getForwardingInterrogationRequired(); // NULL

    ISDNAddressString getVmscAddress(); // OCTET STRING

    MAPExtensionContainer getExtensionContainer(); // SEQUENCE

    NAEAPreferredCI getNaeaPreferredCI(); // SEQUENCE

    CCBSIndicators getCCBSIndicators(); // SEQUENCE

    ISDNAddressString getMsisdn(); // OCTET STRING

    NumberPortabilityStatus getNumberPortabilityStatus(); // ENUMERATED

    Integer getISTAlertTimer(); // INTEGER

    SupportedCamelPhases getSupportedCamelPhasesInVMSC(); // BIT STRING

    OfferedCamel4CSIs getOfferedCamel4CSIsInVMSC(); // BIT STRING

    // This is used as RoutingInfo parameter for V2 and as RoutingInfo2 parameter for MAP V3
    RoutingInfo getRoutingInfo2(); // CHOICE

    ArrayList<SSCode> getSSList2(); // SEQUENCE

    ExtBasicServiceCode getBasicService2(); // CHOICE

    AllowedServices getAllowedServices(); // BIT STRING

    UnavailabilityCause getUnavailabilityCause(); // ENUMERATED

    boolean getReleaseResourcesSupported(); // NULL

    ExternalSignalInfo getGsmBearerCapability(); // SEQUENCE

    long getMapProtocolVersion();
}