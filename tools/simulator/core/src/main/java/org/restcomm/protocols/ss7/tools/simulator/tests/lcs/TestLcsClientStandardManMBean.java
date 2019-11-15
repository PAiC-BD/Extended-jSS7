/*
 * TeleStax, Open Source Cloud Communications
 * Copyright 2011-2018, Telestax Inc and individual contributors
 * by the @authors tag.
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

package org.restcomm.protocols.ss7.tools.simulator.tests.lcs;

import javax.management.MBeanAttributeInfo;
import javax.management.MBeanInfo;
import javax.management.MBeanOperationInfo;
import javax.management.MBeanParameterInfo;
import javax.management.NotCompliantMBeanException;
import javax.management.StandardMBean;

import org.restcomm.protocols.ss7.map.api.service.lsm.ExtGeographicalInformation;
import org.restcomm.protocols.ss7.tools.simulator.common.AddressNatureType;
import org.restcomm.protocols.ss7.tools.simulator.level3.NumberingPlanMapType;

/**
 * @author <a href="mailto:fernando.mendioroz@gmail.com"> Fernando Mendioroz </a>
 * @author <a href="mailto:falonso@csc.om"> Fernando Alonso </a>
 */
public class TestLcsClientStandardManMBean extends StandardMBean {

    public TestLcsClientStandardManMBean(TestLcsClientMan impl, Class<TestLcsClientManMBean> intf) throws NotCompliantMBeanException {
        super(impl, intf);
    }

    @Override
    public MBeanInfo getMBeanInfo() {

        MBeanAttributeInfo[] attributes = new MBeanAttributeInfo[]{
                new MBeanAttributeInfo("AddressNature", AddressNatureType.class.getName(),
                        "AddressNature parameter for address creation (networkNodeNumber,NaESRD)",
                        true, true, false),
                new MBeanAttributeInfo("NumberingPlanType", NumberingPlanMapType.class.getName(),
                        "NumberingPlanType parameter for address creation (networkNodeNumber,NaESRD)",
                        true, true, false),
                new MBeanAttributeInfo("NetworkNodeNumberAddress", String.class.getName(),
                        "NetworkNodeNumber address parameter for response",
                        true, true, false),
                new MBeanAttributeInfo("NaESRDAddress", String.class.getName(),
                        "NaESRD address parameter for response",
                        true, true, false),
                new MBeanAttributeInfo("LCSEventType", LCSEventType.class.getName(),
                        "LCS Event parameter",
                        true, true, false),
                new MBeanAttributeInfo("IMEI", String.class.getName(),
                        "IMEI address parameter",
                        true, true, false),
                new MBeanAttributeInfo("IMSI", String.class.getName(),
                        "IMSI address parameter",
                        true, true, false),
                new MBeanAttributeInfo("MSISDN", String.class.getName(),
                        "MSISDN address parameter",
                        true, true, false),
                new MBeanAttributeInfo("HGMLCAddress", String.class.getName(),
                        "H-GMLC address parameter",
                        true, true, false),
                new MBeanAttributeInfo("LCSReferenceNumber", Integer.class.getName(),
                        "LCS Reference number parameter",
                        true, true, false),
                new MBeanAttributeInfo("MCC", Integer.class.getName(),
                        "MCC parameter for CellId Or SAI",
                        true, true, false),
                new MBeanAttributeInfo("MNC", Integer.class.getName(),
                        "MNC parameter for CellId Or SAI",
                        true, true, false),
                new MBeanAttributeInfo("LAC", Integer.class.getName(),
                        "LAC parameter for CellId Or SAI",
                        true, true, false),
                new MBeanAttributeInfo("CellId", Integer.class.getName(),
                        "CellId parameter for CellId Or SAI",
                        true, true, false),
                new MBeanAttributeInfo("LocationEstimate", ExtGeographicalInformation.class.getName(),
                        "Location Estimate parameter",
                        true, true, false),
                new MBeanAttributeInfo("AgeOfLocationEstimate", Integer.class.getName(),
                        "Age of Location Estimate parameter",
                        true, true, false),
        };

        MBeanParameterInfo[] performSRIResponseParam = new MBeanParameterInfo[]{};

        MBeanParameterInfo[] signString = new MBeanParameterInfo[]{new MBeanParameterInfo("val", String.class.getName(), "Index number or value")};

        MBeanOperationInfo[] operations = new MBeanOperationInfo[]{
                new MBeanOperationInfo("putLCSEventType", "Type parameter for LCS Event creating: "
                        + "0:emergencyCallOrigination,1:emergencyCallRelease,2:molr,3:deferredmtlrResponse", signString,
                        Void.TYPE.getName(), MBeanOperationInfo.ACTION),
                new MBeanOperationInfo(
                        "putAddressNature",
                        "AddressNature parameter for AddressString creating: "
                                + "0:unknown,1:international_number,2:national_significant_number,3:network_specific_number,4:subscriber_number,5:reserved,6:abbreviated_number,7:reserved_for_extension",
                        signString, Void.TYPE.getName(), MBeanOperationInfo.ACTION),
                new MBeanOperationInfo("putNumberingPlanType", "NumberingPlan parameter for AddressString creating: "
                        + "0:unknown,1:ISDN,2:spare_2,3:data,4:telex,5:spare_5,6:land_mobile,7:spare_7,8:national,9:private_plan,15:reserved", signString,
                        Void.TYPE.getName(), MBeanOperationInfo.ACTION),
                new MBeanOperationInfo("performSendRoutingInfoForLCSResponse", "Send Routing Information for LCS response",
                        performSRIResponseParam, String.class.getName(), MBeanOperationInfo.ACTION),
                new MBeanOperationInfo("performProvideSubscriberLocationResponse", "Provide Subscriber Location response",
                        null, String.class.getName(), MBeanOperationInfo.ACTION),
                new MBeanOperationInfo("performSubscriberLocationReportRequest", "Subscriber Location Report request",
                        null, String.class.getName(), MBeanOperationInfo.ACTION),
        };

        return new MBeanInfo(TestLcsClientMan.class.getName(), "LcsClient test parameters management", attributes, null, operations, null);
    }

}
