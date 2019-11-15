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

import java.util.ArrayList;

import org.restcomm.protocols.ss7.map.api.primitives.IMSI;
import org.restcomm.protocols.ss7.map.api.primitives.MAPExtensionContainer;
import org.restcomm.protocols.ss7.map.api.service.mobility.MobilityMessage;
import org.restcomm.protocols.ss7.map.api.service.supplementary.SSCode;

/**
 *
<code>
MAP V1-2-3:

MAP V3: deleteSubscriberData OPERATION ::= {
  --Timer m
  ARGUMENT DeleteSubscriberDataArg
  RESULT DeleteSubscriberDataRes
  --optional
  ERRORS { dataMissing | unexpectedDataValue | unidentifiedSubscriber}
  CODE local:8
}

MAP V2: DeleteSubscriberData ::= OPERATION
--Timer m
ARGUMENT deleteSubscriberDataArg DeleteSubscriberDataArg
RESULT deleteSubscriberDataRes DeleteSubscriberDataRes
-- optional
-- deleteSubscriberDataRes must be absent in version 1
ERRORS { DataMissing, UnexpectedDataValue, UnidentifiedSubscriber}

MAP V3:
DeleteSubscriberDataArg ::= SEQUENCE {
  imsi                            [0] IMSI,
  basicServiceList                [1] BasicServiceList OPTIONAL,
  -- The exception handling for reception of unsupported/not allocated
  -- basicServiceCodes is defined in section 6.8.2
  ss-List                         [2] SS-List OPTIONAL,
  roamingRestrictionDueToUnsupportedFeature [4] NULL OPTIONAL,
  regionalSubscriptionIdentifier  [5] ZoneCode OPTIONAL,
  vbsGroupIndication              [7] NULL OPTIONAL,
  vgcsGroupIndication             [8] NULL OPTIONAL,
  camelSubscriptionInfoWithdraw   [9] NULL OPTIONAL,
  extensionContainer              [6] ExtensionContainer OPTIONAL,
  ...,
  gprsSubscriptionDataWithdraw    [10] GPRSSubscriptionDataWithdraw OPTIONAL,
  roamingRestrictedInSgsnDueToUnsuppportedFeature [11] NULL OPTIONAL,
  lsaInformationWithdraw          [12] LSAInformationWithdraw OPTIONAL,
  gmlc-ListWithdraw               [13] NULL OPTIONAL,
  istInformationWithdraw          [14] NULL OPTIONAL,
  specificCSI-Withdraw            [15] SpecificCSI-Withdraw OPTIONAL,
  chargingCharacteristicsWithdraw [16] NULL OPTIONAL,
  stn-srWithdraw                  [17] NULL OPTIONAL,
  epsSubscriptionDataWithdraw     [18] EPS-SubscriptionDataWithdraw OPTIONAL,
  apn-oi-replacementWithdraw      [19] NULL OPTIONAL,
  csg-SubscriptionDeleted         [20] NULL OPTIONAL
}

MAP V2:
DeleteSubscriberDataArg ::= SEQUENCE {
  imsi                            [0] IMSI,
  basicServiceList                [1] BasicServiceList OPTIONAL,
  ss-List                         [2] SS-List OPTIONAL,
  roamingRestrictionDueToUnsupportedFeature [4] NULL OPTIONAL,
  -- roamingRestrictionDueToUnsupportedFeature must be absent
  -- in version 1
  regionalSubscriptionIdentifier  [5] ZoneCode OPTIONAL,
  -- regionalSubscriptionIdentifier must be absent in version 1
  ...
}

BasicServiceList ::= SEQUENCE SIZE (1..70) OF Ext-BasicServiceCode

SS-List ::= SEQUENCE SIZE (1..30) OF SS-Code
</code>
 *
 *
 * @author sergey vetyutnev
 *
 */
public interface DeleteSubscriberDataRequest extends MobilityMessage {

    IMSI getImsi();

    ArrayList<ExtBasicServiceCode> getBasicServiceList();

    ArrayList<SSCode> getSsList();

    boolean getRoamingRestrictionDueToUnsupportedFeature();

    ZoneCode getRegionalSubscriptionIdentifier();

    boolean getVbsGroupIndication();

    boolean getVgcsGroupIndication();

    boolean getCamelSubscriptionInfoWithdraw();

    MAPExtensionContainer getExtensionContainer();

    GPRSSubscriptionDataWithdraw getGPRSSubscriptionDataWithdraw();

    boolean getRoamingRestrictedInSgsnDueToUnsuppportedFeature();

    LSAInformationWithdraw getLSAInformationWithdraw();

    boolean getGmlcListWithdraw();

    boolean getIstInformationWithdraw();

    SpecificCSIWithdraw getSpecificCSIWithdraw();

    boolean getChargingCharacteristicsWithdraw();

    boolean getStnSrWithdraw();

    EPSSubscriptionDataWithdraw getEPSSubscriptionDataWithdraw();

    boolean getApnOiReplacementWithdraw();

    boolean getCsgSubscriptionDeleted();

}
