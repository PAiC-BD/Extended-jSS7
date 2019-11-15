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

package org.restcomm.protocols.ss7.map.api.service.supplementary;

import java.util.ArrayList;

import org.restcomm.protocols.ss7.map.api.MAPDialog;
import org.restcomm.protocols.ss7.map.api.MAPException;
import org.restcomm.protocols.ss7.map.api.datacoding.CBSDataCodingScheme;
import org.restcomm.protocols.ss7.map.api.primitives.AddressString;
import org.restcomm.protocols.ss7.map.api.primitives.AlertingPattern;
import org.restcomm.protocols.ss7.map.api.primitives.EMLPPPriority;
import org.restcomm.protocols.ss7.map.api.primitives.ISDNAddressString;
import org.restcomm.protocols.ss7.map.api.primitives.USSDString;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.BasicServiceCode;

/**
 *
 * @author amit bhayani
 * @author sergey vetyutnev
 *
 */
public interface MAPDialogSupplementary extends MAPDialog {

    Long addRegisterSSRequest(SSCode ssCode, BasicServiceCode basicService, AddressString forwardedToNumber, ISDNAddressString forwardedToSubaddress,
            Integer noReplyConditionTime, EMLPPPriority defaultPriority, Integer nbrUser, ISDNAddressString longFTNSupported) throws MAPException;

    Long addRegisterSSRequest(int customInvokeTimeout, SSCode ssCode, BasicServiceCode basicService, AddressString forwardedToNumber,
            ISDNAddressString forwardedToSubaddress, Integer noReplyConditionTime, EMLPPPriority defaultPriority, Integer nbrUser,
            ISDNAddressString longFTNSupported) throws MAPException;

    void addRegisterSSResponse(long invokeId, SSInfo ssInfo) throws MAPException;

    Long addEraseSSRequest(SSForBSCode ssForBSCode) throws MAPException;

    Long addEraseSSRequest(int customInvokeTimeout, SSForBSCode ssForBSCode) throws MAPException;

    void addEraseSSResponse(long invokeId, SSInfo ssInfo) throws MAPException;

    Long addActivateSSRequest(SSForBSCode ssForBSCode) throws MAPException;

    Long addActivateSSRequest(int customInvokeTimeout, SSForBSCode ssForBSCode) throws MAPException;

    void addActivateSSResponse(long invokeId, SSInfo ssInfo) throws MAPException;

    Long addDeactivateSSRequest(SSForBSCode ssForBSCode) throws MAPException;

    Long addDeactivateSSRequest(int customInvokeTimeout, SSForBSCode ssForBSCode) throws MAPException;

    void addDeactivateSSResponse(long invokeId, SSInfo ssInfo) throws MAPException;

    Long addInterrogateSSRequest(SSForBSCode ssForBSCode) throws MAPException;

    Long addInterrogateSSRequest(int customInvokeTimeout, SSForBSCode ssForBSCode) throws MAPException;

    void addInterrogateSSResponse_SSStatus(long invokeId, SSStatus ssStatus) throws MAPException;

    void addInterrogateSSResponse_BasicServiceGroupList(long invokeId, ArrayList<BasicServiceCode> basicServiceGroupList) throws MAPException;

    void addInterrogateSSResponse_ForwardingFeatureList(long invokeId, ArrayList<ForwardingFeature> forwardingFeatureList) throws MAPException;

    void addInterrogateSSResponse_GenericServiceInfo(long invokeId, GenericServiceInfo genericServiceInfo) throws MAPException;

    Long addGetPasswordRequest(Long linkedId, GuidanceInfo guidanceInfo) throws MAPException;

    Long addGetPasswordRequest(int customInvokeTimeout, Long linkedId, GuidanceInfo guidanceInfo) throws MAPException;

    void addGetPasswordResponse(long invokeId, Password password) throws MAPException;

    Long addRegisterPasswordRequest(SSCode ssCode) throws MAPException;

    Long addRegisterPasswordRequest(int customInvokeTimeout, SSCode ssCode) throws MAPException;

    void addRegisterPasswordResponse(long invokeId, Password password) throws MAPException;


    /**
     * Add's a new Process Unstructured SS Request as Component.
     *
     * @param ussdDataCodingScheme The Data Coding Scheme for this USSD String as defined in GSM 03.38
     * @param ussdString Ussd String
     * @param alertingPatter The optional alerting pattern. See {@link AlertingPattern}
     * @param msisdn The optional MSISDN in {@link ISDNAddressString} format.
     * @return invokeId
     * @throws MAPException
     */
    Long addProcessUnstructuredSSRequest(CBSDataCodingScheme ussdDataCodingScheme, USSDString ussdString,
            AlertingPattern alertingPatter, ISDNAddressString msisdn) throws MAPException;

    Long addProcessUnstructuredSSRequest(int customInvokeTimeout, CBSDataCodingScheme ussdDataCodingScheme,
            USSDString ussdString, AlertingPattern alertingPatter, ISDNAddressString msisdn) throws MAPException;

    /**
     * Add's a new ProcessUnstructured SS Response as Component.
     *
     * @param invokeId The original invoke ID retrieved from {@link ProcessUnstructuredSSResponse}
     * @param ussdDataCodingScheme The Data Coding Scheme for this USSD String as defined in GSM 03.38
     * @param ussdString Ussd String {@link USSDString}
     * @throws MAPException
     */
    void addProcessUnstructuredSSResponse(long invokeId, CBSDataCodingScheme ussdDataCodingScheme, USSDString ussdString)
            throws MAPException;

    /**
     * Add's a new Unstructured SS Request
     *
     * @param ussdDataCodingScheme The Data Coding Scheme for this USSD String as defined in GSM 03.38
     * @param ussdString Ussd String {@link USSDString}
     * @param alertingPatter The optional alerting pattern. See {@link AlertingPattern}
     * @param msisdn The optional MSISDN in {@link ISDNAddressString} format.
     * @return invokeId
     * @throws MAPException
     */
    Long addUnstructuredSSRequest(CBSDataCodingScheme ussdDataCodingScheme, USSDString ussdString,
            AlertingPattern alertingPatter, ISDNAddressString msisdn) throws MAPException;

    Long addUnstructuredSSRequest(int customInvokeTimeout, CBSDataCodingScheme ussdDataCodingScheme,
            USSDString ussdString, AlertingPattern alertingPatter, ISDNAddressString msisdn) throws MAPException;

    /**
     * Add's a new Unstructured SS Response
     *
     * @param invokeId The original invoke ID retrieved from {@link UnstructuredSSResponse}
     * @param ussdDataCodingScheme The Data Coding Scheme for this USSD String as defined in GSM 03.38
     * @param ussdString Ussd String {@link USSDString}
     * @throws MAPException
     */
    void addUnstructuredSSResponse(long invokeId, CBSDataCodingScheme ussdDataCodingScheme, USSDString ussdString)
            throws MAPException;

    /**
     * Add's a new Unstructured SS Notify
     *
     * @param ussdDataCodingScheme The Data Coding Scheme for this USSD String as defined in GSM 03.38
     * @param ussdString Ussd String {@link USSDString}
     * @param alertingPatter The optional alerting pattern. See {@link AlertingPattern}
     * @param msisdn The optional MSISDN in {@link ISDNAddressString} format.
     * @return invokeId
     * @throws MAPException
     */
    Long addUnstructuredSSNotifyRequest(CBSDataCodingScheme ussdDataCodingScheme, USSDString ussdString,
            AlertingPattern alertingPatter, ISDNAddressString msisdn) throws MAPException;

    Long addUnstructuredSSNotifyRequest(int customInvokeTimeout, CBSDataCodingScheme ussdDataCodingScheme,
            USSDString ussdString, AlertingPattern alertingPatter, ISDNAddressString msisdn) throws MAPException;

    void addUnstructuredSSNotifyResponse(long invokeId) throws MAPException;

}