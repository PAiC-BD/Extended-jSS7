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

import org.restcomm.protocols.ss7.map.api.primitives.AlertingPattern;
import org.restcomm.protocols.ss7.map.api.primitives.EMLPPPriority;
import org.restcomm.protocols.ss7.map.api.primitives.ExtExternalSignalInfo;
import org.restcomm.protocols.ss7.map.api.primitives.ExternalSignalInfo;
import org.restcomm.protocols.ss7.map.api.primitives.IMSI;
import org.restcomm.protocols.ss7.map.api.primitives.ISDNAddressString;
import org.restcomm.protocols.ss7.map.api.primitives.LMSI;
import org.restcomm.protocols.ss7.map.api.primitives.MAPExtensionContainer;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.PagingArea;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.OfferedCamel4CSIs;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.SupportedCamelPhases;

/**
 *
 MAP V1-2-3:
 *
 * MAP V3: provideRoamingNumber OPERATION ::= { --Timer m -- The timer is set to the upper limit of the range if the HLR
 * supports pre-paging. ARGUMENT ProvideRoamingNumberArg RESULT ProvideRoamingNumberRes ERRORS { systemFailure | dataMissing |
 * unexpectedDataValue | facilityNotSupported | or-NotAllowed | absentSubscriber | noRoamingNumberAvailable} CODE local:4 }
 *
 * MAP V2: ProvideRoamingNumber ::= OPERATION--Timer m ARGUMENT provideRoamingNumber ArgProvideRoamingNumberArg RESULT
 * roamingNumber ISDN-AddressString ERRORS { SystemFailure, DataMissing, UnexpectedDataValue, FacilityNotSupported,
 * AbsentSubscriber, NoRoamingNumberAvailable}
 *
 * MAP V3: ProvideRoamingNumberArg ::= SEQUENCE { imsi [0] IMSI, msc-Number [1] ISDN-AddressString, msisdn [2]
 * ISDN-AddressString OPTIONAL, lmsi [4] LMSI OPTIONAL, gsm-BearerCapability [5] ExternalSignalInfo OPTIONAL, networkSignalInfo
 * [6] ExternalSignalInfo OPTIONAL, suppressionOfAnnouncement [7] SuppressionOfAnnouncement OPTIONAL, gmsc-Address [8]
 * ISDN-AddressString OPTIONAL, callReferenceNumber [9] CallReferenceNumber OPTIONAL, or-Interrogation [10] NULL OPTIONAL,
 * extensionContainer [11] ExtensionContainer OPTIONAL, ... , alertingPattern [12] AlertingPattern OPTIONAL, ccbs-Call [13] NULL
 * OPTIONAL, supportedCamelPhasesInInterrogatingNode [15] SupportedCamelPhases OPTIONAL, additionalSignalInfo [14]
 * Ext-ExternalSignalInfo OPTIONAL, orNotSupportedInGMSC [16] NULL OPTIONAL, pre-pagingSupported [17] NULL OPTIONAL,
 * longFTN-Supported [18] NULL OPTIONAL, suppress-VT-CSI [19] NULL OPTIONAL, offeredCamel4CSIsInInterrogatingNode [20]
 * OfferedCamel4CSIs OPTIONAL, mtRoamingRetrySupported [21] NULL OPTIONAL, pagingArea [22] PagingArea OPTIONAL, callPriority
 * [23] EMLPP-Priority OPTIONAL, mtrf-Indicator [24] NULL OPTIONAL, oldMSC-Number [25] ISDN-AddressString OPTIONAL }
 *
 * MAP V2: ProvideRoamingNumberArg ::= SEQUENCE { imsi[0] IMSI, msc-Number[1] ISDN-AddressString OPTIONAL, msc-Number must be
 * present in version greater 1 msisdn[2] ISDN-AddressString OPTIONAL, previousRoamingNumber[3] ISDN-AddressString OPTIONAL,
 * lmsi[4] LMSI OPTIONAL, gsm-BearerCapability[5] ExternalSignalInfo OPTIONAL, networkSignalInfo[6] ExternalSignalInfo OPTIONAL,
 * ...}
 *
 * SuppressionOfAnnouncement ::= NULL
 *
 *
 * @author sergey vetyutnev
 *
 */
public interface ProvideRoamingNumberRequest extends CallHandlingMessage {

     IMSI getImsi();

     ISDNAddressString getMscNumber();

     ISDNAddressString getMsisdn();

     LMSI getLmsi();

     ExternalSignalInfo getGsmBearerCapability();

     ExternalSignalInfo getNetworkSignalInfo();

     boolean getSuppressionOfAnnouncement();

     ISDNAddressString getGmscAddress();

     CallReferenceNumber getCallReferenceNumber();

     boolean getOrInterrogation();

     MAPExtensionContainer getExtensionContainer();

     AlertingPattern getAlertingPattern();

     boolean getCcbsCall();

     SupportedCamelPhases getSupportedCamelPhasesInInterrogatingNode();

     ExtExternalSignalInfo getAdditionalSignalInfo();

     boolean getOrNotSupportedInGMSC();

     boolean getPrePagingSupported();

     boolean getLongFTNSupported();

     boolean getSuppressVtCsi();

     OfferedCamel4CSIs getOfferedCamel4CSIsInInterrogatingNode();

     boolean getMtRoamingRetrySupported();

     PagingArea getPagingArea();

     EMLPPPriority getCallPriority();

     boolean getMtrfIndicator();

     ISDNAddressString getOldMSCNumber();

     long getMapProtocolVersion();

}
