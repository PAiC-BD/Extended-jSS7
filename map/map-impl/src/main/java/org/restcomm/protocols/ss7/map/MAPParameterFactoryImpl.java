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

package org.restcomm.protocols.ss7.map;

import java.nio.charset.Charset;
import java.util.ArrayList;

import org.mobicents.protocols.asn.BitSetStrictLength;
import org.restcomm.protocols.ss7.isup.message.parameter.LocationNumber;
import org.restcomm.protocols.ss7.map.api.MAPException;
import org.restcomm.protocols.ss7.map.api.MAPParameterFactory;
import org.restcomm.protocols.ss7.map.api.datacoding.CBSDataCodingScheme;
import org.restcomm.protocols.ss7.map.api.dialog.MAPUserAbortChoice;
import org.restcomm.protocols.ss7.map.api.primitives.AddressNature;
import org.restcomm.protocols.ss7.map.api.primitives.AddressString;
import org.restcomm.protocols.ss7.map.api.primitives.AlertingPattern;
import org.restcomm.protocols.ss7.map.api.primitives.CellGlobalIdOrServiceAreaIdFixedLength;
import org.restcomm.protocols.ss7.map.api.primitives.CellGlobalIdOrServiceAreaIdOrLAI;
import org.restcomm.protocols.ss7.map.api.primitives.DiameterIdentity;
import org.restcomm.protocols.ss7.map.api.primitives.EMLPPPriority;
import org.restcomm.protocols.ss7.map.api.primitives.FTNAddressString;
import org.restcomm.protocols.ss7.map.api.primitives.GSNAddress;
import org.restcomm.protocols.ss7.map.api.primitives.GSNAddressAddressType;
import org.restcomm.protocols.ss7.map.api.primitives.GlobalCellId;
import org.restcomm.protocols.ss7.map.api.primitives.IMEI;
import org.restcomm.protocols.ss7.map.api.primitives.IMSI;
import org.restcomm.protocols.ss7.map.api.primitives.ISDNAddressString;
import org.restcomm.protocols.ss7.map.api.primitives.ISDNSubaddressString;
import org.restcomm.protocols.ss7.map.api.primitives.LAIFixedLength;
import org.restcomm.protocols.ss7.map.api.primitives.LMSI;
import org.restcomm.protocols.ss7.map.api.primitives.MAPExtensionContainer;
import org.restcomm.protocols.ss7.map.api.primitives.MAPPrivateExtension;
import org.restcomm.protocols.ss7.map.api.primitives.NAEACIC;
import org.restcomm.protocols.ss7.map.api.primitives.NAEAPreferredCI;
import org.restcomm.protocols.ss7.map.api.primitives.NetworkIdentificationPlanValue;
import org.restcomm.protocols.ss7.map.api.primitives.NetworkIdentificationTypeValue;
import org.restcomm.protocols.ss7.map.api.primitives.NumberingPlan;
import org.restcomm.protocols.ss7.map.api.primitives.PlmnId;
import org.restcomm.protocols.ss7.map.api.primitives.SubscriberIdentity;
import org.restcomm.protocols.ss7.map.api.primitives.TMSI;
import org.restcomm.protocols.ss7.map.api.primitives.Time;
import org.restcomm.protocols.ss7.map.api.primitives.USSDString;
import org.restcomm.protocols.ss7.map.api.service.callhandling.CUGCheckInfo;
import org.restcomm.protocols.ss7.map.api.service.callhandling.CallReferenceNumber;
import org.restcomm.protocols.ss7.map.api.service.callhandling.CamelInfo;
import org.restcomm.protocols.ss7.map.api.service.callhandling.CamelRoutingInfo;
import org.restcomm.protocols.ss7.map.api.service.callhandling.ExtendedRoutingInfo;
import org.restcomm.protocols.ss7.map.api.service.callhandling.ForwardingData;
import org.restcomm.protocols.ss7.map.api.service.callhandling.GmscCamelSubscriptionInfo;
import org.restcomm.protocols.ss7.map.api.service.callhandling.RoutingInfo;
import org.restcomm.protocols.ss7.map.api.service.callhandling.UUData;
import org.restcomm.protocols.ss7.map.api.service.callhandling.UUI;
import org.restcomm.protocols.ss7.map.api.service.callhandling.UUIndicator;
import org.restcomm.protocols.ss7.map.api.service.lsm.AddGeographicalInformation;
import org.restcomm.protocols.ss7.map.api.service.lsm.AdditionalNumber;
import org.restcomm.protocols.ss7.map.api.service.lsm.Area;
import org.restcomm.protocols.ss7.map.api.service.lsm.AreaDefinition;
import org.restcomm.protocols.ss7.map.api.service.lsm.AreaEventInfo;
import org.restcomm.protocols.ss7.map.api.service.lsm.AreaIdentification;
import org.restcomm.protocols.ss7.map.api.service.lsm.AreaType;
import org.restcomm.protocols.ss7.map.api.service.lsm.DeferredLocationEventType;
import org.restcomm.protocols.ss7.map.api.service.lsm.DeferredmtlrData;
import org.restcomm.protocols.ss7.map.api.service.lsm.ExtGeographicalInformation;
import org.restcomm.protocols.ss7.map.api.service.lsm.GeranGANSSpositioningData;
import org.restcomm.protocols.ss7.map.api.service.lsm.LCSClientExternalID;
import org.restcomm.protocols.ss7.map.api.service.lsm.LCSClientID;
import org.restcomm.protocols.ss7.map.api.service.lsm.LCSClientInternalID;
import org.restcomm.protocols.ss7.map.api.service.lsm.LCSClientName;
import org.restcomm.protocols.ss7.map.api.service.lsm.LCSClientType;
import org.restcomm.protocols.ss7.map.api.service.lsm.LCSCodeword;
import org.restcomm.protocols.ss7.map.api.service.lsm.LCSFormatIndicator;
import org.restcomm.protocols.ss7.map.api.service.lsm.LCSLocationInfo;
import org.restcomm.protocols.ss7.map.api.service.lsm.LCSPrivacyCheck;
import org.restcomm.protocols.ss7.map.api.service.lsm.LCSQoS;
import org.restcomm.protocols.ss7.map.api.service.lsm.LCSRequestorID;
import org.restcomm.protocols.ss7.map.api.service.lsm.LocationEstimateType;
import org.restcomm.protocols.ss7.map.api.service.lsm.LocationType;
import org.restcomm.protocols.ss7.map.api.service.lsm.OccurrenceInfo;
import org.restcomm.protocols.ss7.map.api.service.lsm.PeriodicLDRInfo;
import org.restcomm.protocols.ss7.map.api.service.lsm.PositioningDataInformation;
import org.restcomm.protocols.ss7.map.api.service.lsm.PrivacyCheckRelatedAction;
import org.restcomm.protocols.ss7.map.api.service.lsm.RANTechnology;
import org.restcomm.protocols.ss7.map.api.service.lsm.ReportingPLMN;
import org.restcomm.protocols.ss7.map.api.service.lsm.ReportingPLMNList;
import org.restcomm.protocols.ss7.map.api.service.lsm.ResponseTime;
import org.restcomm.protocols.ss7.map.api.service.lsm.ResponseTimeCategory;
import org.restcomm.protocols.ss7.map.api.service.lsm.SLRArgExtensionContainer;
import org.restcomm.protocols.ss7.map.api.service.lsm.SLRArgPCSExtensions;
import org.restcomm.protocols.ss7.map.api.service.lsm.ServingNodeAddress;
import org.restcomm.protocols.ss7.map.api.service.lsm.SupportedGADShapes;
import org.restcomm.protocols.ss7.map.api.service.lsm.TerminationCause;
import org.restcomm.protocols.ss7.map.api.service.lsm.UtranGANSSpositioningData;
import org.restcomm.protocols.ss7.map.api.service.lsm.UtranPositioningDataInfo;
import org.restcomm.protocols.ss7.map.api.service.lsm.VelocityEstimate;
import org.restcomm.protocols.ss7.map.api.service.lsm.VelocityType;
import org.restcomm.protocols.ss7.map.api.service.mobility.authentication.AuthenticationQuintuplet;
import org.restcomm.protocols.ss7.map.api.service.mobility.authentication.AuthenticationSetList;
import org.restcomm.protocols.ss7.map.api.service.mobility.authentication.AuthenticationTriplet;
import org.restcomm.protocols.ss7.map.api.service.mobility.authentication.CK;
import org.restcomm.protocols.ss7.map.api.service.mobility.authentication.Cksn;
import org.restcomm.protocols.ss7.map.api.service.mobility.authentication.CurrentSecurityContext;
import org.restcomm.protocols.ss7.map.api.service.mobility.authentication.EpcAv;
import org.restcomm.protocols.ss7.map.api.service.mobility.authentication.EpsAuthenticationSetList;
import org.restcomm.protocols.ss7.map.api.service.mobility.authentication.GSMSecurityContextData;
import org.restcomm.protocols.ss7.map.api.service.mobility.authentication.IK;
import org.restcomm.protocols.ss7.map.api.service.mobility.authentication.KSI;
import org.restcomm.protocols.ss7.map.api.service.mobility.authentication.Kc;
import org.restcomm.protocols.ss7.map.api.service.mobility.authentication.QuintupletList;
import org.restcomm.protocols.ss7.map.api.service.mobility.authentication.ReSynchronisationInfo;
import org.restcomm.protocols.ss7.map.api.service.mobility.authentication.TripletList;
import org.restcomm.protocols.ss7.map.api.service.mobility.authentication.UMTSSecurityContextData;
import org.restcomm.protocols.ss7.map.api.service.mobility.imei.RequestedEquipmentInfo;
import org.restcomm.protocols.ss7.map.api.service.mobility.imei.UESBIIu;
import org.restcomm.protocols.ss7.map.api.service.mobility.imei.UESBIIuA;
import org.restcomm.protocols.ss7.map.api.service.mobility.imei.UESBIIuB;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.ADDInfo;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.AgeIndicator;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.EPSInfo;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.IMSIWithLMSI;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.ISRInformation;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.ISTSupportIndicator;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.LAC;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.LocationArea;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.PDNGWUpdate;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.PagingArea;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.SGSNCapability;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.SuperChargerInfo;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.SupportedFeatures;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.SupportedLCSCapabilitySets;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.SupportedRATTypes;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.VLRCapability;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.AdditionalRequestedCAMELSubscriptionInfo;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.AnyTimeInterrogationRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.AnyTimeInterrogationResponse;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.CAMELSubscriptionInfo;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.CallBarringData;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.CallForwardingData;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.CallHoldData;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.CallWaitingData;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.ClipData;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.ClirData;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.DomainType;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.EUtranCgi;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.EctData;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.ExtCwFeature;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.GPRSChargingID;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.GPRSMSClass;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.GeodeticInformation;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.GeographicalInformation;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.LIPAPermission;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.LocationInformation;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.LocationInformationEPS;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.LocationInformationGPRS;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.LocationNumberMap;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.MNPInfoRes;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.MSClassmark2;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.MSISDNBS;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.MSNetworkCapability;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.MSRadioAccessCapability;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.NotReachableReason;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.NumberPortabilityStatus;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.ODBInfo;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.PDPContext;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.PDPContextInfo;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.PSSubscriberState;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.PSSubscriberStateChoice;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.RAIdentity;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.RequestedCAMELSubscriptionInfo;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.RequestedInfo;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.RequestedServingNode;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.RequestedSubscriptionInfo;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.RouteingNumber;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.SIPTOPermission;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.SubscriberInfo;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.SubscriberState;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.SubscriberStateChoice;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.TAId;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.TEID;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.TransactionId;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.TypeOfShape;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.UserCSGInformation;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.AMBR;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.APN;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.APNConfiguration;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.APNConfigurationProfile;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.APNOIReplacement;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.AccessRestrictionData;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.AdditionalInfo;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.AdditionalSubscriptions;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.AllocationRetentionPriority;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.BasicServiceCode;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.BearerServiceCode;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.BearerServiceCodeValue;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.CSAllocationRetentionPriority;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.CSGId;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.CSGSubscriptionData;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.CUGFeature;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.CUGInfo;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.CUGInterlock;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.CUGSubscription;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.CallTypeCriteria;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.CauseValue;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ChargingCharacteristics;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.DCSI;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.DPAnalysedInfoCriterium;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.DefaultCallHandling;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.DefaultGPRSHandling;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.DestinationNumberCriteria;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.EMLPPInfo;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.EPSQoSSubscribed;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.EPSSubscriptionData;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.Ext2QoSSubscribed;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.Ext3QoSSubscribed;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.Ext4QoSSubscribed;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtBasicServiceCode;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtBearerServiceCode;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtCallBarInfo;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtCallBarringFeature;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtForwFeature;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtForwInfo;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtForwOptions;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtForwOptionsForwardingReason;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtPDPType;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtQoSSubscribed;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtSSData;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtSSInfo;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtSSStatus;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtTeleserviceCode;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExternalClient;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.FQDN;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.GMLCRestriction;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.GPRSCSI;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.GPRSCamelTDPData;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.GPRSSubscriptionData;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.GPRSTriggerDetectionPoint;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.InterCUGRestrictions;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.InterCUGRestrictionsValue;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.IntraCUGOptions;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.LCSInformation;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.LCSPrivacyClass;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.LSAAttributes;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.LSAData;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.LSAIdentity;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.LSAInformation;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.LSAOnlyAccessIndicator;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.MCSI;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.MCSSInfo;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.MGCSI;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.MMCode;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.MMCodeValue;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.MOLRClass;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.MTSMSTPDUType;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.MTsmsCAMELTDPCriteria;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.MatchType;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.NotificationToMSUser;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.OBcsmCamelTDPData;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.OBcsmCamelTdpCriteria;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.OBcsmTriggerDetectionPoint;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.OCSI;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ODBData;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.OfferedCamel4CSIs;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.PDNGWAllocationType;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.PDNGWIdentity;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.PDNType;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.PDPAddress;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.PDPType;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.QoSClassIdentifier;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.QoSSubscribed;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.SMSTriggerDetectionPoint;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ServiceType;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.SpecificAPNInfo;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.SupportedCamelPhases;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.TBcsmCamelTDPData;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.TBcsmCamelTdpCriteria;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.TBcsmTriggerDetectionPoint;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.TCSI;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.TeleserviceCode;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.TeleserviceCodeValue;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ZoneCode;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ODBGeneralData;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ODBHPLMNData;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.PDNTypeValue;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.SGSNCAMELSubscriptionInfo;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.SMSCSI;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.SMSCAMELTDPData;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.DefaultSMSHandling;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.SSCamelData;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.SSCSI;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.VlrCamelSubscriptionInfo;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.VoiceBroadcastData;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.GroupId;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.VoiceGroupCallData;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.LongGroupId;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.CauseValueCodeValue;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.LSAIdentificationPriorityValue;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.Category;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.CategoryValue;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.OfferedCamel4Functionalities;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.GPRSSubscriptionDataWithdraw;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.LSAInformationWithdraw;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.SpecificCSIWithdraw;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.EPSSubscriptionDataWithdraw;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.CUGIndex;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.PDPTypeValue;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.QoSSubscribed_ReliabilityClass;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.QoSSubscribed_DelayClass;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.QoSSubscribed_PrecedenceClass;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.QoSSubscribed_PeakThroughput;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.QoSSubscribed_MeanThroughput;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtQoSSubscribed_MaximumSduSize;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtQoSSubscribed_BitRate;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtQoSSubscribed_BitRateExtended;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtQoSSubscribed_TransferDelay;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtQoSSubscribed_DeliveryOfErroneousSdus;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtQoSSubscribed_DeliveryOrder;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtQoSSubscribed_TrafficClass;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtQoSSubscribed_SduErrorRatio;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtQoSSubscribed_ResidualBER;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.ExtQoSSubscribed_TrafficHandlingPriority;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.Ext2QoSSubscribed_SourceStatisticsDescriptor;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.CAMELSubscriptionInfoImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.CallBarringDataImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.CallForwardingDataImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.CallHoldDataImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.CallWaitingDataImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.ClipDataImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.ClirDataImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.EctDataImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.ExtCwFeatureImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.MSISDNBSImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.ODBInfoImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.RequestedSubscriptionInfoImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.AMBRImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.APNConfigurationImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.APNConfigurationProfileImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.APNImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.APNOIReplacementImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.AccessRestrictionDataImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.AdditionalInfoImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.AdditionalSubscriptionsImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.AgeIndicatorImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.BasicServiceCodeImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.BearerServiceCodeImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.CSAllocationRetentionPriorityImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.CSGIdImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.CSGSubscriptionDataImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.CUGFeatureImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.CUGIndexImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.CUGInfoImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.CUGInterlockImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.CUGSubscriptionImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.CategoryImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.CauseValueImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.ChargingCharacteristicsImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.DCSIImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.DPAnalysedInfoCriteriumImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.DestinationNumberCriteriaImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.EMLPPInfoImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.EPSQoSSubscribedImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.EPSSubscriptionDataImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.EPSSubscriptionDataWithdrawImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.Ext2QoSSubscribedImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.Ext3QoSSubscribedImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.Ext4QoSSubscribedImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.ExtBasicServiceCodeImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.ExtBearerServiceCodeImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.ExtCallBarInfoImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.ExtCallBarringFeatureImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.ExtForwFeatureImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.ExtForwInfoImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.ExtForwOptionsImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.ExtPDPTypeImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.ExtQoSSubscribedImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.ExtSSDataImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.ExtSSInfoImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.ExtSSStatusImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.ExtTeleserviceCodeImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.ExternalClientImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.FQDNImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.GPRSCSIImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.GPRSCamelTDPDataImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.GPRSSubscriptionDataImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.GPRSSubscriptionDataWithdrawImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.GroupIdImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.InterCUGRestrictionsImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.LCSInformationImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.LCSPrivacyClassImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.LSAAttributesImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.LSADataImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.LSAIdentityImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.LSAInformationImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.LSAInformationWithdrawImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.LongGroupIdImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.MCSIImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.MCSSInfoImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.MGCSIImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.MMCodeImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.MOLRClassImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.MTsmsCAMELTDPCriteriaImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.OBcsmCamelTDPDataImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.OBcsmCamelTdpCriteriaImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.OCSIImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.ODBDataImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.ODBGeneralDataImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.ODBHPLMNDataImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.OfferedCamel4CSIsImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.OfferedCamel4FunctionalitiesImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.PDNGWIdentityImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.PDNTypeImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.PDPAddressImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.PDPTypeImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.QoSSubscribedImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.SGSNCAMELSubscriptionInfoImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.SMSCAMELTDPDataImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.SMSCSIImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.SSCSIImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.SSCamelDataImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.ServiceTypeImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.SpecificAPNInfoImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.SpecificCSIWithdrawImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.SupportedCamelPhasesImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.TBcsmCamelTDPDataImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.TBcsmCamelTdpCriteriaImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.TCSIImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.TeleserviceCodeImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.VlrCamelSubscriptionInfoImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.VoiceBroadcastDataImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.VoiceGroupCallDataImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.ZoneCodeImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.ExtQoSSubscribed_MaximumSduSizeImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.ExtQoSSubscribed_BitRateImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.ExtQoSSubscribed_BitRateExtendedImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.ExtQoSSubscribed_TransferDelayImpl;
import org.restcomm.protocols.ss7.map.api.service.oam.AreaScope;
import org.restcomm.protocols.ss7.map.api.service.oam.BMSCEventList;
import org.restcomm.protocols.ss7.map.api.service.oam.BMSCInterfaceList;
import org.restcomm.protocols.ss7.map.api.service.oam.BssRecordType;
import org.restcomm.protocols.ss7.map.api.service.oam.ENBInterfaceList;
import org.restcomm.protocols.ss7.map.api.service.oam.GGSNEventList;
import org.restcomm.protocols.ss7.map.api.service.oam.GGSNInterfaceList;
import org.restcomm.protocols.ss7.map.api.service.oam.HlrRecordType;
import org.restcomm.protocols.ss7.map.api.service.oam.JobType;
import org.restcomm.protocols.ss7.map.api.service.oam.ListOfMeasurements;
import org.restcomm.protocols.ss7.map.api.service.oam.LoggingDuration;
import org.restcomm.protocols.ss7.map.api.service.oam.LoggingInterval;
import org.restcomm.protocols.ss7.map.api.service.oam.MDTConfiguration;
import org.restcomm.protocols.ss7.map.api.service.oam.MGWEventList;
import org.restcomm.protocols.ss7.map.api.service.oam.MGWInterfaceList;
import org.restcomm.protocols.ss7.map.api.service.oam.MMEEventList;
import org.restcomm.protocols.ss7.map.api.service.oam.MMEInterfaceList;
import org.restcomm.protocols.ss7.map.api.service.oam.MSCSEventList;
import org.restcomm.protocols.ss7.map.api.service.oam.MSCSInterfaceList;
import org.restcomm.protocols.ss7.map.api.service.oam.MscRecordType;
import org.restcomm.protocols.ss7.map.api.service.oam.PGWEventList;
import org.restcomm.protocols.ss7.map.api.service.oam.PGWInterfaceList;
import org.restcomm.protocols.ss7.map.api.service.oam.RNCInterfaceList;
import org.restcomm.protocols.ss7.map.api.service.oam.ReportAmount;
import org.restcomm.protocols.ss7.map.api.service.oam.ReportInterval;
import org.restcomm.protocols.ss7.map.api.service.oam.ReportingTrigger;
import org.restcomm.protocols.ss7.map.api.service.oam.SGSNEventList;
import org.restcomm.protocols.ss7.map.api.service.oam.SGSNInterfaceList;
import org.restcomm.protocols.ss7.map.api.service.oam.SGWEventList;
import org.restcomm.protocols.ss7.map.api.service.oam.SGWInterfaceList;
import org.restcomm.protocols.ss7.map.api.service.oam.TraceDepth;
import org.restcomm.protocols.ss7.map.api.service.oam.TraceDepthList;
import org.restcomm.protocols.ss7.map.api.service.oam.TraceEventList;
import org.restcomm.protocols.ss7.map.api.service.oam.TraceInterfaceList;
import org.restcomm.protocols.ss7.map.api.service.oam.TraceNETypeList;
import org.restcomm.protocols.ss7.map.api.service.oam.TraceReference;
import org.restcomm.protocols.ss7.map.api.service.oam.TraceType;
import org.restcomm.protocols.ss7.map.api.service.oam.TraceTypeInvokingEvent;
import org.restcomm.protocols.ss7.map.api.service.sms.CorrelationID;
import org.restcomm.protocols.ss7.map.api.service.sms.IpSmGwGuidance;
import org.restcomm.protocols.ss7.map.api.service.sms.LocationInfoWithLMSI;
import org.restcomm.protocols.ss7.map.api.service.sms.MWStatus;
import org.restcomm.protocols.ss7.map.api.service.sms.SM_RP_DA;
import org.restcomm.protocols.ss7.map.api.service.sms.SM_RP_OA;
import org.restcomm.protocols.ss7.map.api.service.sms.SM_RP_SMEA;
import org.restcomm.protocols.ss7.map.api.service.sms.SipUri;
import org.restcomm.protocols.ss7.map.api.service.sms.SmsSignalInfo;
import org.restcomm.protocols.ss7.map.api.service.supplementary.CCBSFeature;
import org.restcomm.protocols.ss7.map.api.service.supplementary.CallBarringFeature;
import org.restcomm.protocols.ss7.map.api.service.supplementary.CallBarringInfo;
import org.restcomm.protocols.ss7.map.api.service.supplementary.CliRestrictionOption;
import org.restcomm.protocols.ss7.map.api.service.supplementary.ForwardingFeature;
import org.restcomm.protocols.ss7.map.api.service.supplementary.ForwardingInfo;
import org.restcomm.protocols.ss7.map.api.service.supplementary.ForwardingOptions;
import org.restcomm.protocols.ss7.map.api.service.supplementary.GenericServiceInfo;
import org.restcomm.protocols.ss7.map.api.service.supplementary.OverrideCategory;
import org.restcomm.protocols.ss7.map.api.service.supplementary.Password;
import org.restcomm.protocols.ss7.map.api.service.supplementary.ProcessUnstructuredSSRequest;
import org.restcomm.protocols.ss7.map.api.service.supplementary.ProcessUnstructuredSSResponse;
import org.restcomm.protocols.ss7.map.api.service.supplementary.SSCode;
import org.restcomm.protocols.ss7.map.api.service.supplementary.SSData;
import org.restcomm.protocols.ss7.map.api.service.supplementary.SSForBSCode;
import org.restcomm.protocols.ss7.map.api.service.supplementary.SSInfo;
import org.restcomm.protocols.ss7.map.api.service.supplementary.SSStatus;
import org.restcomm.protocols.ss7.map.api.service.supplementary.SSSubscriptionOption;
import org.restcomm.protocols.ss7.map.api.service.supplementary.SupplementaryCodeValue;
import org.restcomm.protocols.ss7.map.api.service.supplementary.UnstructuredSSNotifyRequest;
import org.restcomm.protocols.ss7.map.api.service.supplementary.UnstructuredSSNotifyResponse;
import org.restcomm.protocols.ss7.map.api.service.supplementary.UnstructuredSSRequest;
import org.restcomm.protocols.ss7.map.api.service.supplementary.UnstructuredSSResponse;
import org.restcomm.protocols.ss7.map.api.smstpdu.AddressField;
import org.restcomm.protocols.ss7.map.api.smstpdu.SmsTpdu;
import org.restcomm.protocols.ss7.tcap.asn.comp.GeneralProblemType;
import org.restcomm.protocols.ss7.tcap.asn.comp.InvokeProblemType;
import org.restcomm.protocols.ss7.tcap.asn.comp.Problem;
import org.restcomm.protocols.ss7.tcap.asn.comp.ProblemType;
import org.restcomm.protocols.ss7.tcap.asn.comp.ReturnErrorProblemType;
import org.restcomm.protocols.ss7.tcap.asn.comp.ReturnResultProblemType;
import org.restcomm.protocols.ss7.map.dialog.MAPUserAbortChoiceImpl;
import org.restcomm.protocols.ss7.map.primitives.AddressStringImpl;
import org.restcomm.protocols.ss7.map.primitives.CellGlobalIdOrServiceAreaIdFixedLengthImpl;
import org.restcomm.protocols.ss7.map.primitives.CellGlobalIdOrServiceAreaIdOrLAIImpl;
import org.restcomm.protocols.ss7.map.primitives.DiameterIdentityImpl;
import org.restcomm.protocols.ss7.map.primitives.FTNAddressStringImpl;
import org.restcomm.protocols.ss7.map.primitives.GSNAddressImpl;
import org.restcomm.protocols.ss7.map.primitives.GlobalCellIdImpl;
import org.restcomm.protocols.ss7.map.primitives.IMEIImpl;
import org.restcomm.protocols.ss7.map.primitives.IMSIImpl;
import org.restcomm.protocols.ss7.map.primitives.ISDNAddressStringImpl;
import org.restcomm.protocols.ss7.map.primitives.ISDNSubaddressStringImpl;
import org.restcomm.protocols.ss7.map.primitives.LAIFixedLengthImpl;
import org.restcomm.protocols.ss7.map.primitives.LMSIImpl;
import org.restcomm.protocols.ss7.map.primitives.MAPExtensionContainerImpl;
import org.restcomm.protocols.ss7.map.primitives.MAPPrivateExtensionImpl;
import org.restcomm.protocols.ss7.map.primitives.NAEACICImpl;
import org.restcomm.protocols.ss7.map.primitives.NAEAPreferredCIImpl;
import org.restcomm.protocols.ss7.map.primitives.PlmnIdImpl;
import org.restcomm.protocols.ss7.map.primitives.SubscriberIdentityImpl;
import org.restcomm.protocols.ss7.map.primitives.TMSIImpl;
import org.restcomm.protocols.ss7.map.primitives.TimeImpl;
import org.restcomm.protocols.ss7.map.primitives.USSDStringImpl;
import org.restcomm.protocols.ss7.map.service.callhandling.CUGCheckInfoImpl;
import org.restcomm.protocols.ss7.map.service.callhandling.CallReferenceNumberImpl;
import org.restcomm.protocols.ss7.map.service.callhandling.CamelInfoImpl;
import org.restcomm.protocols.ss7.map.service.callhandling.CamelRoutingInfoImpl;
import org.restcomm.protocols.ss7.map.service.callhandling.ExtendedRoutingInfoImpl;
import org.restcomm.protocols.ss7.map.service.callhandling.GmscCamelSubscriptionInfoImpl;
import org.restcomm.protocols.ss7.map.service.callhandling.RoutingInfoImpl;
import org.restcomm.protocols.ss7.map.service.callhandling.UUDataImpl;
import org.restcomm.protocols.ss7.map.service.callhandling.UUIImpl;
import org.restcomm.protocols.ss7.map.service.callhandling.UUIndicatorImpl;
import org.restcomm.protocols.ss7.map.service.lsm.AddGeographicalInformationImpl;
import org.restcomm.protocols.ss7.map.service.lsm.AdditionalNumberImpl;
import org.restcomm.protocols.ss7.map.service.lsm.AreaDefinitionImpl;
import org.restcomm.protocols.ss7.map.service.lsm.AreaEventInfoImpl;
import org.restcomm.protocols.ss7.map.service.lsm.AreaIdentificationImpl;
import org.restcomm.protocols.ss7.map.service.lsm.AreaImpl;
import org.restcomm.protocols.ss7.map.service.lsm.DeferredLocationEventTypeImpl;
import org.restcomm.protocols.ss7.map.service.lsm.DeferredmtlrDataImpl;
import org.restcomm.protocols.ss7.map.service.lsm.ExtGeographicalInformationImpl;
import org.restcomm.protocols.ss7.map.service.lsm.GeranGANSSpositioningDataImpl;
import org.restcomm.protocols.ss7.map.service.lsm.LCSClientExternalIDImpl;
import org.restcomm.protocols.ss7.map.service.lsm.LCSClientIDImpl;
import org.restcomm.protocols.ss7.map.service.lsm.LCSClientNameImpl;
import org.restcomm.protocols.ss7.map.service.lsm.LCSCodewordImpl;
import org.restcomm.protocols.ss7.map.service.lsm.LCSLocationInfoImpl;
import org.restcomm.protocols.ss7.map.service.lsm.LCSPrivacyCheckImpl;
import org.restcomm.protocols.ss7.map.service.lsm.LCSQoSImpl;
import org.restcomm.protocols.ss7.map.service.lsm.LCSRequestorIDImpl;
import org.restcomm.protocols.ss7.map.service.lsm.LocationTypeImpl;
import org.restcomm.protocols.ss7.map.service.lsm.PeriodicLDRInfoImpl;
import org.restcomm.protocols.ss7.map.service.lsm.PositioningDataInformationImpl;
import org.restcomm.protocols.ss7.map.service.lsm.ReportingPLMNImpl;
import org.restcomm.protocols.ss7.map.service.lsm.ReportingPLMNListImpl;
import org.restcomm.protocols.ss7.map.service.lsm.ResponseTimeImpl;
import org.restcomm.protocols.ss7.map.service.lsm.SLRArgExtensionContainerImpl;
import org.restcomm.protocols.ss7.map.service.lsm.SLRArgPCSExtensionsImpl;
import org.restcomm.protocols.ss7.map.service.lsm.ServingNodeAddressImpl;
import org.restcomm.protocols.ss7.map.service.lsm.SupportedGADShapesImpl;
import org.restcomm.protocols.ss7.map.service.lsm.UtranGANSSpositioningDataImpl;
import org.restcomm.protocols.ss7.map.service.lsm.UtranPositioningDataInfoImpl;
import org.restcomm.protocols.ss7.map.service.lsm.VelocityEstimateImpl;
import org.restcomm.protocols.ss7.map.service.mobility.authentication.AuthenticationQuintupletImpl;
import org.restcomm.protocols.ss7.map.service.mobility.authentication.AuthenticationSetListImpl;
import org.restcomm.protocols.ss7.map.service.mobility.authentication.AuthenticationTripletImpl;
import org.restcomm.protocols.ss7.map.service.mobility.authentication.CKImpl;
import org.restcomm.protocols.ss7.map.service.mobility.authentication.CksnImpl;
import org.restcomm.protocols.ss7.map.service.mobility.authentication.CurrentSecurityContextImpl;
import org.restcomm.protocols.ss7.map.service.mobility.authentication.EpcAvImpl;
import org.restcomm.protocols.ss7.map.service.mobility.authentication.EpsAuthenticationSetListImpl;
import org.restcomm.protocols.ss7.map.service.mobility.authentication.GSMSecurityContextDataImpl;
import org.restcomm.protocols.ss7.map.service.mobility.authentication.IKImpl;
import org.restcomm.protocols.ss7.map.service.mobility.authentication.KSIImpl;
import org.restcomm.protocols.ss7.map.service.mobility.authentication.KcImpl;
import org.restcomm.protocols.ss7.map.service.mobility.authentication.QuintupletListImpl;
import org.restcomm.protocols.ss7.map.service.mobility.authentication.ReSynchronisationInfoImpl;
import org.restcomm.protocols.ss7.map.service.mobility.authentication.TripletListImpl;
import org.restcomm.protocols.ss7.map.service.mobility.authentication.UMTSSecurityContextDataImpl;
import org.restcomm.protocols.ss7.map.service.mobility.imei.RequestedEquipmentInfoImpl;
import org.restcomm.protocols.ss7.map.service.mobility.imei.UESBIIuAImpl;
import org.restcomm.protocols.ss7.map.service.mobility.imei.UESBIIuBImpl;
import org.restcomm.protocols.ss7.map.service.mobility.imei.UESBIIuImpl;
import org.restcomm.protocols.ss7.map.service.mobility.locationManagement.ADDInfoImpl;
import org.restcomm.protocols.ss7.map.service.mobility.locationManagement.EPSInfoImpl;
import org.restcomm.protocols.ss7.map.service.mobility.locationManagement.IMSIWithLMSIImpl;
import org.restcomm.protocols.ss7.map.service.mobility.locationManagement.ISRInformationImpl;
import org.restcomm.protocols.ss7.map.service.mobility.locationManagement.LACImpl;
import org.restcomm.protocols.ss7.map.service.mobility.locationManagement.LocationAreaImpl;
import org.restcomm.protocols.ss7.map.service.mobility.locationManagement.PDNGWUpdateImpl;
import org.restcomm.protocols.ss7.map.service.mobility.locationManagement.PagingAreaImpl;
import org.restcomm.protocols.ss7.map.service.mobility.locationManagement.SGSNCapabilityImpl;
import org.restcomm.protocols.ss7.map.service.mobility.locationManagement.SuperChargerInfoImpl;
import org.restcomm.protocols.ss7.map.service.mobility.locationManagement.SupportedFeaturesImpl;
import org.restcomm.protocols.ss7.map.service.mobility.locationManagement.SupportedLCSCapabilitySetsImpl;
import org.restcomm.protocols.ss7.map.service.mobility.locationManagement.SupportedRATTypesImpl;
import org.restcomm.protocols.ss7.map.service.mobility.locationManagement.VLRCapabilityImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.AnyTimeInterrogationRequestImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.AnyTimeInterrogationResponseImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.EUtranCgiImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.GPRSChargingIDImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.GPRSMSClassImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.GeodeticInformationImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.GeographicalInformationImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.LocationInformationEPSImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.LocationInformationGPRSImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.LocationInformationImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.LocationNumberMapImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.MNPInfoResImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.MSClassmark2Impl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.MSNetworkCapabilityImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.MSRadioAccessCapabilityImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.PDPContextImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.PDPContextInfoImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.PSSubscriberStateImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.RAIdentityImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.RequestedInfoImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.RouteingNumberImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.SubscriberInfoImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.SubscriberStateImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.TAIdImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.TEIDImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.TransactionIdImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.UserCSGInformationImpl;
import org.restcomm.protocols.ss7.map.service.oam.AreaScopeImpl;
import org.restcomm.protocols.ss7.map.service.oam.BMSCEventListImpl;
import org.restcomm.protocols.ss7.map.service.oam.BMSCInterfaceListImpl;
import org.restcomm.protocols.ss7.map.service.oam.ENBInterfaceListImpl;
import org.restcomm.protocols.ss7.map.service.oam.GGSNEventListImpl;
import org.restcomm.protocols.ss7.map.service.oam.GGSNInterfaceListImpl;
import org.restcomm.protocols.ss7.map.service.oam.ListOfMeasurementsImpl;
import org.restcomm.protocols.ss7.map.service.oam.MDTConfigurationImpl;
import org.restcomm.protocols.ss7.map.service.oam.MGWEventListImpl;
import org.restcomm.protocols.ss7.map.service.oam.MGWInterfaceListImpl;
import org.restcomm.protocols.ss7.map.service.oam.MMEEventListImpl;
import org.restcomm.protocols.ss7.map.service.oam.MMEInterfaceListImpl;
import org.restcomm.protocols.ss7.map.service.oam.MSCSEventListImpl;
import org.restcomm.protocols.ss7.map.service.oam.MSCSInterfaceListImpl;
import org.restcomm.protocols.ss7.map.service.oam.PGWEventListImpl;
import org.restcomm.protocols.ss7.map.service.oam.PGWInterfaceListImpl;
import org.restcomm.protocols.ss7.map.service.oam.RNCInterfaceListImpl;
import org.restcomm.protocols.ss7.map.service.oam.ReportingTriggerImpl;
import org.restcomm.protocols.ss7.map.service.oam.SGSNEventListImpl;
import org.restcomm.protocols.ss7.map.service.oam.SGSNInterfaceListImpl;
import org.restcomm.protocols.ss7.map.service.oam.SGWEventListImpl;
import org.restcomm.protocols.ss7.map.service.oam.SGWInterfaceListImpl;
import org.restcomm.protocols.ss7.map.service.oam.TraceDepthListImpl;
import org.restcomm.protocols.ss7.map.service.oam.TraceEventListImpl;
import org.restcomm.protocols.ss7.map.service.oam.TraceInterfaceListImpl;
import org.restcomm.protocols.ss7.map.service.oam.TraceNETypeListImpl;
import org.restcomm.protocols.ss7.map.service.oam.TraceReferenceImpl;
import org.restcomm.protocols.ss7.map.service.oam.TraceTypeImpl;
import org.restcomm.protocols.ss7.map.service.sms.CorrelationIDImpl;
import org.restcomm.protocols.ss7.map.service.sms.IpSmGwGuidanceImpl;
import org.restcomm.protocols.ss7.map.service.sms.LocationInfoWithLMSIImpl;
import org.restcomm.protocols.ss7.map.service.sms.MWStatusImpl;
import org.restcomm.protocols.ss7.map.service.sms.SM_RP_DAImpl;
import org.restcomm.protocols.ss7.map.service.sms.SM_RP_OAImpl;
import org.restcomm.protocols.ss7.map.service.sms.SM_RP_SMEAImpl;
import org.restcomm.protocols.ss7.map.service.sms.SipUriImpl;
import org.restcomm.protocols.ss7.map.service.sms.SmsSignalInfoImpl;
import org.restcomm.protocols.ss7.map.service.supplementary.CCBSFeatureImpl;
import org.restcomm.protocols.ss7.map.service.supplementary.CallBarringFeatureImpl;
import org.restcomm.protocols.ss7.map.service.supplementary.CallBarringInfoImpl;
import org.restcomm.protocols.ss7.map.service.supplementary.ForwardingFeatureImpl;
import org.restcomm.protocols.ss7.map.service.supplementary.ForwardingInfoImpl;
import org.restcomm.protocols.ss7.map.service.supplementary.GenericServiceInfoImpl;
import org.restcomm.protocols.ss7.map.service.supplementary.PasswordImpl;
import org.restcomm.protocols.ss7.map.service.supplementary.ProcessUnstructuredSSRequestImpl;
import org.restcomm.protocols.ss7.map.service.supplementary.ProcessUnstructuredSSResponseImpl;
import org.restcomm.protocols.ss7.map.service.supplementary.SSCodeImpl;
import org.restcomm.protocols.ss7.map.service.supplementary.SSDataImpl;
import org.restcomm.protocols.ss7.map.service.supplementary.SSForBSCodeImpl;
import org.restcomm.protocols.ss7.map.service.supplementary.SSInfoImpl;
import org.restcomm.protocols.ss7.map.service.supplementary.SSStatusImpl;
import org.restcomm.protocols.ss7.map.service.supplementary.SSSubscriptionOptionImpl;
import org.restcomm.protocols.ss7.map.service.supplementary.UnstructuredSSNotifyRequestImpl;
import org.restcomm.protocols.ss7.map.service.supplementary.UnstructuredSSNotifyResponseImpl;
import org.restcomm.protocols.ss7.map.service.supplementary.UnstructuredSSRequestImpl;
import org.restcomm.protocols.ss7.map.service.supplementary.UnstructuredSSResponseImpl;
import org.restcomm.protocols.ss7.tcap.asn.TcapFactory;


/**
 *
 * @author amit bhayani
 * @author sergey vetyutnev
 * @author <a href="mailto:fernando.mendioroz@gmail.com"> Fernando Mendioroz </a>
 */
public class MAPParameterFactoryImpl implements MAPParameterFactory {

    public ProcessUnstructuredSSRequest createProcessUnstructuredSSRequestIndication(CBSDataCodingScheme ussdDataCodingSch,
            USSDString ussdString, AlertingPattern alertingPattern, ISDNAddressString msisdnAddressString) {

        ProcessUnstructuredSSRequest request = new ProcessUnstructuredSSRequestImpl(ussdDataCodingSch, ussdString,
                alertingPattern, msisdnAddressString);
        return request;
    }

    public ProcessUnstructuredSSResponse createProcessUnstructuredSSResponseIndication(
            CBSDataCodingScheme ussdDataCodingScheme, USSDString ussdString) {
        ProcessUnstructuredSSResponse response = new ProcessUnstructuredSSResponseImpl(ussdDataCodingScheme, ussdString);
        return response;
    }

    public UnstructuredSSRequest createUnstructuredSSRequestIndication(CBSDataCodingScheme ussdDataCodingSch,
            USSDString ussdString, AlertingPattern alertingPattern, ISDNAddressString msisdnAddressString) {
        UnstructuredSSRequest request = new UnstructuredSSRequestImpl(ussdDataCodingSch, ussdString, alertingPattern,
                msisdnAddressString);
        return request;
    }

    public UnstructuredSSResponse createUnstructuredSSRequestIndication(CBSDataCodingScheme ussdDataCodingScheme,
            USSDString ussdString) {
        UnstructuredSSResponse response = new UnstructuredSSResponseImpl(ussdDataCodingScheme, ussdString);
        return response;
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.MAPParameterFactory#createUnstructuredSSNotifyRequestIndication(byte,
     * org.restcomm.protocols.ss7.map.api.primitives.USSDString,
     * org.restcomm.protocols.ss7.map.api.primitives.AlertingPattern,
     * org.restcomm.protocols.ss7.map.api.primitives.ISDNAddressString)
     */
    public UnstructuredSSNotifyRequest createUnstructuredSSNotifyRequestIndication(CBSDataCodingScheme ussdDataCodingSch,
            USSDString ussdString, AlertingPattern alertingPattern, ISDNAddressString msisdnAddressString) {
        UnstructuredSSNotifyRequest request = new UnstructuredSSNotifyRequestImpl(ussdDataCodingSch, ussdString,
                alertingPattern, msisdnAddressString);
        return request;
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.MAPParameterFactory#createUnstructuredSSNotifyResponseIndication()
     */
    public UnstructuredSSNotifyResponse createUnstructuredSSNotifyResponseIndication() {
        UnstructuredSSNotifyResponse response = new UnstructuredSSNotifyResponseImpl();
        return response;
    }

    public USSDString createUSSDString(String ussdString, CBSDataCodingScheme dataCodingScheme, Charset gsm8Charset)
            throws MAPException {
        return new USSDStringImpl(ussdString, dataCodingScheme, gsm8Charset);
    }

    public USSDString createUSSDString(String ussdString) throws MAPException {
        return new USSDStringImpl(ussdString, null, null);
    }

    public USSDString createUSSDString(byte[] ussdString, CBSDataCodingScheme dataCodingScheme, Charset gsm8Charset) {
        return new USSDStringImpl(ussdString, dataCodingScheme);
    }

    public USSDString createUSSDString(byte[] ussdString) {
        return new USSDStringImpl(ussdString, null);
    }

    public AddressString createAddressString(AddressNature addNature, NumberingPlan numPlan, String address) {
        return new AddressStringImpl(addNature, numPlan, address);
    }

    public AddressString createAddressString(boolean isExtension, AddressNature addNature, NumberingPlan numPlan, String address) {
        return new AddressStringImpl(addNature, numPlan, address);
    }

    public ISDNAddressString createISDNAddressString(AddressNature addNature, NumberingPlan numPlan, String address) {
        return new ISDNAddressStringImpl(addNature, numPlan, address);
    }

    public ISDNAddressString createISDNAddressString(boolean extension, AddressNature addNature, NumberingPlan numPlan, String address) {
        return new ISDNAddressStringImpl(extension, addNature, numPlan, address);
    }

    public FTNAddressString createFTNAddressString(AddressNature addNature, NumberingPlan numPlan, String address) {
        return new FTNAddressStringImpl(addNature, numPlan, address);
    }

    public MAPUserAbortChoice createMAPUserAbortChoice() {
        MAPUserAbortChoiceImpl mapUserAbortChoice = new MAPUserAbortChoiceImpl();
        return mapUserAbortChoice;
    }

    public MAPPrivateExtension createMAPPrivateExtension(long[] oId, byte[] data) {
        return new MAPPrivateExtensionImpl(oId, data);
    }

    public MAPExtensionContainer createMAPExtensionContainer(ArrayList<MAPPrivateExtension> privateExtensionList,
            byte[] pcsExtensions) {
        return new MAPExtensionContainerImpl(privateExtensionList, pcsExtensions);
    }

    public IMSI createIMSI(String data) {
        return new IMSIImpl(data);
    }

    public IMEI createIMEI(String imei) {
        return new IMEIImpl(imei);
    }

    public LMSI createLMSI(byte[] data) {
        return new LMSIImpl(data);
    }

    public SM_RP_DA createSM_RP_DA(IMSI imsi) {
        return new SM_RP_DAImpl(imsi);
    }

    public SM_RP_DA createSM_RP_DA(LMSI lmsi) {
        return new SM_RP_DAImpl(lmsi);
    }

    public SM_RP_DA createSM_RP_DA(AddressString serviceCentreAddressDA) {
        return new SM_RP_DAImpl(serviceCentreAddressDA);
    }

    public SM_RP_DA createSM_RP_DA() {
        return new SM_RP_DAImpl();
    }

    public SM_RP_OA createSM_RP_OA_Msisdn(ISDNAddressString msisdn) {
        SM_RP_OAImpl res = new SM_RP_OAImpl();
        res.setMsisdn(msisdn);
        return res;
    }

    public SM_RP_OA createSM_RP_OA_ServiceCentreAddressOA(AddressString serviceCentreAddressOA) {
        SM_RP_OAImpl res = new SM_RP_OAImpl();
        res.setServiceCentreAddressOA(serviceCentreAddressOA);
        return res;
    }

    public SM_RP_OA createSM_RP_OA() {
        return new SM_RP_OAImpl();
    }

    public SmsSignalInfo createSmsSignalInfo(byte[] data, Charset gsm8Charset) {
        return new SmsSignalInfoImpl(data, gsm8Charset);
    }

    public SmsSignalInfo createSmsSignalInfo(SmsTpdu data, Charset gsm8Charset) throws MAPException {
        return new SmsSignalInfoImpl(data, gsm8Charset);
    }

    public SM_RP_SMEA createSM_RP_SMEA(byte[] data) {
        return new SM_RP_SMEAImpl(data);
    }

    public SM_RP_SMEA createSM_RP_SMEA(AddressField addressField) throws MAPException {
        return new SM_RP_SMEAImpl(addressField);
    }

    public MWStatus createMWStatus(boolean scAddressNotIncluded, boolean mnrfSet, boolean mcefSet, boolean mnrgSet) {
        return new MWStatusImpl(scAddressNotIncluded, mnrfSet, mcefSet, mnrgSet);
    }

    public LocationInfoWithLMSI createLocationInfoWithLMSI(ISDNAddressString networkNodeNumber, LMSI lmsi, MAPExtensionContainer extensionContainer,
            boolean gprsNodeIndicator, AdditionalNumber additionalNumber) {
        return new LocationInfoWithLMSIImpl(networkNodeNumber, lmsi, extensionContainer, gprsNodeIndicator, additionalNumber);
    }

    public Problem createProblemGeneral(GeneralProblemType prob) {
        Problem pb = TcapFactory.createProblem(ProblemType.General);
        pb.setGeneralProblemType(prob);
        return pb;
    }

    public Problem createProblemInvoke(InvokeProblemType prob) {
        Problem pb = TcapFactory.createProblem(ProblemType.Invoke);
        pb.setInvokeProblemType(prob);
        return pb;
    }

    public Problem createProblemResult(ReturnResultProblemType prob) {
        Problem pb = TcapFactory.createProblem(ProblemType.ReturnResult);
        pb.setReturnResultProblemType(prob);
        return pb;
    }

    public Problem createProblemError(ReturnErrorProblemType prob) {
        Problem pb = TcapFactory.createProblem(ProblemType.ReturnError);
        pb.setReturnErrorProblemType(prob);
        return pb;
    }

    public CellGlobalIdOrServiceAreaIdOrLAI createCellGlobalIdOrServiceAreaIdOrLAI(
            CellGlobalIdOrServiceAreaIdFixedLength cellGlobalIdOrServiceAreaIdFixedLength) {
        return new CellGlobalIdOrServiceAreaIdOrLAIImpl(cellGlobalIdOrServiceAreaIdFixedLength);
    }

    public CellGlobalIdOrServiceAreaIdOrLAI createCellGlobalIdOrServiceAreaIdOrLAI(LAIFixedLength laiFixedLength) {
        return new CellGlobalIdOrServiceAreaIdOrLAIImpl(laiFixedLength);
    }

    public CellGlobalIdOrServiceAreaIdFixedLength createCellGlobalIdOrServiceAreaIdFixedLength(byte[] data) {
        return new CellGlobalIdOrServiceAreaIdFixedLengthImpl(data);
    }

    public CellGlobalIdOrServiceAreaIdFixedLength createCellGlobalIdOrServiceAreaIdFixedLength(int mcc, int mnc, int lac,
            int cellIdOrServiceAreaCode) throws MAPException {
        return new CellGlobalIdOrServiceAreaIdFixedLengthImpl(mcc, mnc, lac, cellIdOrServiceAreaCode);
    }

    public LAIFixedLength createLAIFixedLength(byte[] data) {
        return new LAIFixedLengthImpl(data);
    }

    public LAIFixedLength createLAIFixedLength(int mcc, int mnc, int lac) throws MAPException {
        return new LAIFixedLengthImpl(mcc, mnc, lac);
    }

    public CallReferenceNumber createCallReferenceNumber(byte[] data) {
        return new CallReferenceNumberImpl(data);
    }

    public LocationInformation createLocationInformation(Integer ageOfLocationInformation,
            GeographicalInformation geographicalInformation, ISDNAddressString vlrNumber, LocationNumberMap locationNumber,
            CellGlobalIdOrServiceAreaIdOrLAI cellGlobalIdOrServiceAreaIdOrLAI, MAPExtensionContainer extensionContainer,
            LSAIdentity selectedLSAId, ISDNAddressString mscNumber, GeodeticInformation geodeticInformation,
            boolean currentLocationRetrieved, boolean saiPresent, LocationInformationEPS locationInformationEPS,
            UserCSGInformation userCSGInformation) {
        return new LocationInformationImpl(ageOfLocationInformation, geographicalInformation, vlrNumber, locationNumber,
                cellGlobalIdOrServiceAreaIdOrLAI, extensionContainer, selectedLSAId, mscNumber, geodeticInformation,
                currentLocationRetrieved, saiPresent, locationInformationEPS, userCSGInformation);
    }

    public LocationNumberMap createLocationNumberMap(byte[] data) {
        return new LocationNumberMapImpl(data);
    }

    public LocationNumberMap createLocationNumberMap(LocationNumber locationNumber) throws MAPException {
        return new LocationNumberMapImpl(locationNumber);
    }

    public SubscriberState createSubscriberState(SubscriberStateChoice subscriberStateChoice,
            NotReachableReason notReachableReason) {
        return new SubscriberStateImpl(subscriberStateChoice, notReachableReason);
    }

    public ExtBasicServiceCode createExtBasicServiceCode(ExtBearerServiceCode extBearerServiceCode) {
        return new ExtBasicServiceCodeImpl(extBearerServiceCode);
    }

    public ExtBasicServiceCode createExtBasicServiceCode(ExtTeleserviceCode extTeleserviceCode) {
        return new ExtBasicServiceCodeImpl(extTeleserviceCode);
    }

    public ExtBearerServiceCode createExtBearerServiceCode(byte[] data) {
        return new ExtBearerServiceCodeImpl(data);
    }

    public ExtBearerServiceCode createExtBearerServiceCode(BearerServiceCodeValue value) {
        return new ExtBearerServiceCodeImpl(value);
    }

    public BearerServiceCode createBearerServiceCode(int data) {
        return new BearerServiceCodeImpl(data);
    }

    public BearerServiceCode createBearerServiceCode(BearerServiceCodeValue value) {
        return new BearerServiceCodeImpl(value);
    }

    public ExtTeleserviceCode createExtTeleserviceCode(byte[] data) {
        return new ExtTeleserviceCodeImpl(data);
    }

    public ExtTeleserviceCode createExtTeleserviceCode(TeleserviceCodeValue value) {
        return new ExtTeleserviceCodeImpl(value);
    }

    public TeleserviceCode createTeleserviceCode(int data) {
        return new TeleserviceCodeImpl(data);
    }

    public TeleserviceCode createTeleserviceCode(TeleserviceCodeValue value) {
        return new TeleserviceCodeImpl(value);
    }

    public AuthenticationTriplet createAuthenticationTriplet(byte[] rand, byte[] sres, byte[] kc) {
        return new AuthenticationTripletImpl(rand, sres, kc);
    }

    public AuthenticationQuintuplet createAuthenticationQuintuplet(byte[] rand, byte[] xres, byte[] ck, byte[] ik, byte[] autn) {
        return new AuthenticationQuintupletImpl(rand, xres, ck, ik, autn);
    }

    public TripletList createTripletList(ArrayList<AuthenticationTriplet> authenticationTriplets) {
        return new TripletListImpl(authenticationTriplets);
    }

    public QuintupletList createQuintupletList(ArrayList<AuthenticationQuintuplet> quintupletList) {
        return new QuintupletListImpl(quintupletList);
    }

    public AuthenticationSetList createAuthenticationSetList(TripletList tripletList) {
        return new AuthenticationSetListImpl(tripletList);
    }

    public AuthenticationSetList createAuthenticationSetList(QuintupletList quintupletList) {
        return new AuthenticationSetListImpl(quintupletList);
    }

    public PlmnId createPlmnId(byte[] data) {
        return new PlmnIdImpl(data);
    }

    public PlmnId createPlmnId(int mcc, int mnc) {
        return new PlmnIdImpl(mcc, mnc);
    }

    public GSNAddress createGSNAddress(byte[] data) {
        return new GSNAddressImpl(data);
    }

    public GSNAddress createGSNAddress(GSNAddressAddressType addressType, byte[] addressData) throws MAPException {
        return new GSNAddressImpl(addressType, addressData);
    }

    public ReSynchronisationInfo createReSynchronisationInfo(byte[] rand, byte[] auts) {
        return new ReSynchronisationInfoImpl(rand, auts);
    }

    public EpsAuthenticationSetList createEpsAuthenticationSetList(ArrayList<EpcAv> epcAv) {
        return new EpsAuthenticationSetListImpl(epcAv);
    }

    public EpcAv createEpcAv(byte[] rand, byte[] xres, byte[] autn, byte[] kasme, MAPExtensionContainer extensionContainer) {
        return new EpcAvImpl(rand, xres, autn, kasme, extensionContainer);
    }

    public VLRCapability createVlrCapability(SupportedCamelPhases supportedCamelPhases,
            MAPExtensionContainer extensionContainer, boolean solsaSupportIndicator, ISTSupportIndicator istSupportIndicator,
            SuperChargerInfo superChargerSupportedInServingNetworkEntity, boolean longFtnSupported,
            SupportedLCSCapabilitySets supportedLCSCapabilitySets, OfferedCamel4CSIs offeredCamel4CSIs,
            SupportedRATTypes supportedRATTypesIndicator, boolean longGroupIDSupported, boolean mtRoamingForwardingSupported) {
        return new VLRCapabilityImpl(supportedCamelPhases, extensionContainer, solsaSupportIndicator, istSupportIndicator,
                superChargerSupportedInServingNetworkEntity, longFtnSupported, supportedLCSCapabilitySets, offeredCamel4CSIs,
                supportedRATTypesIndicator, longGroupIDSupported, mtRoamingForwardingSupported);
    }

    public SupportedCamelPhases createSupportedCamelPhases(boolean phase1, boolean phase2, boolean phase3, boolean phase4) {
        return new SupportedCamelPhasesImpl(phase1, phase2, phase3, phase4);
    }

    public SuperChargerInfo createSuperChargerInfo(Boolean sendSubscriberData) {
        return new SuperChargerInfoImpl(sendSubscriberData);
    }

    public SuperChargerInfo createSuperChargerInfo(byte[] subscriberDataStored) {
        return new SuperChargerInfoImpl(subscriberDataStored);
    }

    public SupportedLCSCapabilitySets createSupportedLCSCapabilitySets(boolean lcsCapabilitySetRelease98_99,
            boolean lcsCapabilitySetRelease4, boolean lcsCapabilitySetRelease5, boolean lcsCapabilitySetRelease6,
            boolean lcsCapabilitySetRelease7) {
        return new SupportedLCSCapabilitySetsImpl(lcsCapabilitySetRelease98_99, lcsCapabilitySetRelease4,
                lcsCapabilitySetRelease5, lcsCapabilitySetRelease6, lcsCapabilitySetRelease7);
    }

    public OfferedCamel4CSIs createOfferedCamel4CSIs(boolean oCsi, boolean dCsi, boolean vtCsi, boolean tCsi, boolean mtSMSCsi,
            boolean mgCsi, boolean psiEnhancements) {
        return new OfferedCamel4CSIsImpl(oCsi, dCsi, vtCsi, tCsi, mtSMSCsi, mgCsi, psiEnhancements);
    }

    public SupportedRATTypes createSupportedRATTypes(boolean utran, boolean geran, boolean gan, boolean i_hspa_evolution,
            boolean e_utran) {
        return new SupportedRATTypesImpl(utran, geran, gan, i_hspa_evolution, e_utran);
    }

    public ADDInfo createADDInfo(IMEI imeisv, boolean skipSubscriberDataUpdate) {
        return new ADDInfoImpl(imeisv, skipSubscriberDataUpdate);
    }

    public PagingArea createPagingArea(ArrayList<LocationArea> locationAreas) {
        return new PagingAreaImpl(locationAreas);
    }

    public LAC createLAC(byte[] data) {
        return new LACImpl(data);
    }

    public LAC createLAC(int lac) throws MAPException {
        return new LACImpl(lac);
    }

    public LocationArea createLocationArea(LAIFixedLength laiFixedLength) {
        return new LocationAreaImpl(laiFixedLength);
    }

    public LocationArea createLocationArea(LAC lac) {
        return new LocationAreaImpl(lac);
    }

    public AnyTimeInterrogationRequest createAnyTimeInterrogationRequest(SubscriberIdentity subscriberIdentity,
            RequestedInfo requestedInfo, ISDNAddressString gsmSCFAddress, MAPExtensionContainer extensionContainer) {
        return new AnyTimeInterrogationRequestImpl(subscriberIdentity, requestedInfo, gsmSCFAddress, extensionContainer);
    }

    public AnyTimeInterrogationResponse createAnyTimeInterrogationResponse(SubscriberInfo subscriberInfo,
            MAPExtensionContainer extensionContainer) {
        return new AnyTimeInterrogationResponseImpl(subscriberInfo, extensionContainer);
    }

    public DiameterIdentity createDiameterIdentity(byte[] data) {
        return new DiameterIdentityImpl(data);
    }

    public SubscriberIdentity createSubscriberIdentity(IMSI imsi) {
        return new SubscriberIdentityImpl(imsi);
    }

    public SubscriberIdentity createSubscriberIdentity(ISDNAddressString msisdn) {
        return new SubscriberIdentityImpl(msisdn);
    }

    public APN createAPN(byte[] data) {
        return new APNImpl(data);
    }

    @Override
    public APN createAPN(String data) throws MAPException {
        return new APNImpl(data);
    }

    public PDPAddress createPDPAddress(byte[] data) {
        return new PDPAddressImpl(data);
    }

    public PDPType createPDPType(byte[] data) {
        return new PDPTypeImpl(data);
    }

    @Override
    public PDPType createPDPType(PDPTypeValue data) {
        return new PDPTypeImpl(data);
    }

    public PDPContextInfo createPDPContextInfo(int pdpContextIdentifier, boolean pdpContextActive, PDPType pdpType,
            PDPAddress pdpAddress, APN apnSubscribed, APN apnInUse, Integer asapi, TransactionId transactionId,
            TEID teidForGnAndGp, TEID teidForIu, GSNAddress ggsnAddress, ExtQoSSubscribed qosSubscribed,
            ExtQoSSubscribed qosRequested, ExtQoSSubscribed qosNegotiated, GPRSChargingID chargingId,
            ChargingCharacteristics chargingCharacteristics, GSNAddress rncAddress, MAPExtensionContainer extensionContainer,
            Ext2QoSSubscribed qos2Subscribed, Ext2QoSSubscribed qos2Requested, Ext2QoSSubscribed qos2Negotiated,
            Ext3QoSSubscribed qos3Subscribed, Ext3QoSSubscribed qos3Requested, Ext3QoSSubscribed qos3Negotiated,
            Ext4QoSSubscribed qos4Subscribed, Ext4QoSSubscribed qos4Requested, Ext4QoSSubscribed qos4Negotiated,
            ExtPDPType extPdpType, PDPAddress extPdpAddress) {
        return new PDPContextInfoImpl(pdpContextIdentifier, pdpContextActive, pdpType, pdpAddress, apnSubscribed, apnInUse,
                asapi, transactionId, teidForGnAndGp, teidForIu, ggsnAddress, qosSubscribed, qosRequested, qosNegotiated,
                chargingId, chargingCharacteristics, rncAddress, extensionContainer, qos2Subscribed, qos2Requested,
                qos2Negotiated, qos3Subscribed, qos3Requested, qos3Negotiated, qos4Subscribed, qos4Requested, qos4Negotiated,
                extPdpType, extPdpAddress);
    }

    public CSGId createCSGId(BitSetStrictLength data) {
        return new CSGIdImpl(data);
    }

    public LSAIdentity createLSAIdentity(byte[] data) {
        return new LSAIdentityImpl(data);
    }

    public GPRSChargingID createGPRSChargingID(byte[] data) {
        return new GPRSChargingIDImpl(data);
    }

    public ChargingCharacteristics createChargingCharacteristics(byte[] data) {
        return new ChargingCharacteristicsImpl(data);
    }

    @Override
    public ChargingCharacteristics createChargingCharacteristics(boolean isNormalCharging, boolean isPrepaidCharging, boolean isFlatRateChargingCharging,
            boolean isChargingByHotBillingCharging) {
        return new ChargingCharacteristicsImpl(isNormalCharging, isPrepaidCharging, isFlatRateChargingCharging, isChargingByHotBillingCharging);
    }

    public ExtQoSSubscribed createExtQoSSubscribed(byte[] data) {
        return new ExtQoSSubscribedImpl(data);
    }

    @Override
    public ExtQoSSubscribed createExtQoSSubscribed(int allocationRetentionPriority, ExtQoSSubscribed_DeliveryOfErroneousSdus deliveryOfErroneousSdus,
            ExtQoSSubscribed_DeliveryOrder deliveryOrder, ExtQoSSubscribed_TrafficClass trafficClass, ExtQoSSubscribed_MaximumSduSize maximumSduSize,
            ExtQoSSubscribed_BitRate maximumBitRateForUplink, ExtQoSSubscribed_BitRate maximumBitRateForDownlink, ExtQoSSubscribed_ResidualBER residualBER,
            ExtQoSSubscribed_SduErrorRatio sduErrorRatio, ExtQoSSubscribed_TrafficHandlingPriority trafficHandlingPriority,
            ExtQoSSubscribed_TransferDelay transferDelay, ExtQoSSubscribed_BitRate guaranteedBitRateForUplink,
            ExtQoSSubscribed_BitRate guaranteedBitRateForDownlink) {
        return new ExtQoSSubscribedImpl(allocationRetentionPriority, deliveryOfErroneousSdus, deliveryOrder, trafficClass, maximumSduSize,
                maximumBitRateForUplink, maximumBitRateForDownlink, residualBER, sduErrorRatio, trafficHandlingPriority, transferDelay,
                guaranteedBitRateForUplink, guaranteedBitRateForDownlink);
    }

    public Ext2QoSSubscribed createExt2QoSSubscribed(byte[] data) {
        return new Ext2QoSSubscribedImpl(data);
    }

    @Override
    public Ext2QoSSubscribed createExt2QoSSubscribed(Ext2QoSSubscribed_SourceStatisticsDescriptor sourceStatisticsDescriptor,
            boolean optimisedForSignallingTraffic, ExtQoSSubscribed_BitRateExtended maximumBitRateForDownlinkExtended,
            ExtQoSSubscribed_BitRateExtended guaranteedBitRateForDownlinkExtended) {
        return new Ext2QoSSubscribedImpl(sourceStatisticsDescriptor, optimisedForSignallingTraffic, maximumBitRateForDownlinkExtended,
                guaranteedBitRateForDownlinkExtended);
    }

    public Ext3QoSSubscribed createExt3QoSSubscribed(byte[] data) {
        return new Ext3QoSSubscribedImpl(data);
    }

    @Override
    public Ext3QoSSubscribed createExt3QoSSubscribed(ExtQoSSubscribed_BitRateExtended maximumBitRateForUplinkExtended,
            ExtQoSSubscribed_BitRateExtended guaranteedBitRateForUplinkExtended) {
        return new Ext3QoSSubscribedImpl(maximumBitRateForUplinkExtended, guaranteedBitRateForUplinkExtended);
    }

    public Ext4QoSSubscribed createExt4QoSSubscribed(int data) {
        return new Ext4QoSSubscribedImpl(data);
    }

    public ExtPDPType createExtPDPType(byte[] data) {
        return new ExtPDPTypeImpl(data);
    }

    public TransactionId createTransactionId(byte[] data) {
        return new TransactionIdImpl(data);
    }

    public TAId createTAId(byte[] data) {
        return new TAIdImpl(data);
    }

    public RAIdentity createRAIdentity(byte[] data) {
        return new RAIdentityImpl(data);
    }

    public EUtranCgi createEUtranCgi(byte[] data) {
        return new EUtranCgiImpl(data);
    }

    public TEID createTEID(byte[] data) {
        return new TEIDImpl(data);
    }

    public GPRSMSClass createGPRSMSClass(MSNetworkCapability mSNetworkCapability,
            MSRadioAccessCapability mSRadioAccessCapability) {
        return new GPRSMSClassImpl(mSNetworkCapability, mSRadioAccessCapability);
    }

    public GeodeticInformation createGeodeticInformation(byte[] data) {
        return new GeodeticInformationImpl(data);
    }

    public GeographicalInformation createGeographicalInformation(byte[] data) {
        return new GeographicalInformationImpl(data);
    }

    public LocationInformationEPS createLocationInformationEPS(EUtranCgi eUtranCellGlobalIdentity, TAId trackingAreaIdentity,
            MAPExtensionContainer extensionContainer, GeographicalInformation geographicalInformation,
            GeodeticInformation geodeticInformation, boolean currentLocationRetrieved, Integer ageOfLocationInformation,
            DiameterIdentity mmeName) {
        return new LocationInformationEPSImpl(eUtranCellGlobalIdentity, trackingAreaIdentity, extensionContainer,
                geographicalInformation, geodeticInformation, currentLocationRetrieved, ageOfLocationInformation, mmeName);
    }

    public LocationInformationGPRS createLocationInformationGPRS(
            CellGlobalIdOrServiceAreaIdOrLAI cellGlobalIdOrServiceAreaIdOrLAI, RAIdentity routeingAreaIdentity,
            GeographicalInformation geographicalInformation, ISDNAddressString sgsnNumber, LSAIdentity selectedLSAIdentity,
            MAPExtensionContainer extensionContainer, boolean saiPresent, GeodeticInformation geodeticInformation,
            boolean currentLocationRetrieved, Integer ageOfLocationInformation) {
        return new LocationInformationGPRSImpl(cellGlobalIdOrServiceAreaIdOrLAI, routeingAreaIdentity, geographicalInformation,
                sgsnNumber, selectedLSAIdentity, extensionContainer, saiPresent, geodeticInformation, currentLocationRetrieved,
                ageOfLocationInformation);
    }

    public MSNetworkCapability createMSNetworkCapability(byte[] data) {
        return new MSNetworkCapabilityImpl(data);
    }

    public MSRadioAccessCapability createMSRadioAccessCapability(byte[] data) {
        return new MSRadioAccessCapabilityImpl(data);
    }

    public MSClassmark2 createMSClassmark2(byte[] data) {
        return new MSClassmark2Impl(data);
    }

    public MNPInfoRes createMNPInfoRes(RouteingNumber routeingNumber, IMSI imsi, ISDNAddressString msisdn,
            NumberPortabilityStatus numberPortabilityStatus, MAPExtensionContainer extensionContainer) {
        return new MNPInfoResImpl(routeingNumber, imsi, msisdn, numberPortabilityStatus, extensionContainer);
    }

    public RequestedInfo createRequestedInfo(boolean locationInformation, boolean subscriberState,
                                             MAPExtensionContainer extensionContainer, boolean currentLocation, DomainType requestedDomain, boolean imei,
                                             boolean msClassmark, boolean mnpRequestedInfo, boolean locationInformationEPSSupported) {
        return new RequestedInfoImpl(locationInformation, subscriberState, extensionContainer, currentLocation,
            requestedDomain, imei, msClassmark, mnpRequestedInfo, locationInformationEPSSupported);
    }

    public RequestedInfo createRequestedInfo(boolean locationInformation, boolean subscriberState,
                                             MAPExtensionContainer extensionContainer, boolean currentLocation, DomainType requestedDomain, boolean imei,
                                             boolean msClassmark, boolean mnpRequestedInfo, boolean locationInformationEPSSupported, boolean tadsData,
                                             RequestedServingNode requestedServingNode, boolean servingNodeIndication, boolean localTimeZoneRequest) {
        return new RequestedInfoImpl(locationInformation, subscriberState, extensionContainer, currentLocation, requestedDomain, imei, msClassmark,
            mnpRequestedInfo, tadsData, requestedServingNode, servingNodeIndication, locationInformationEPSSupported, localTimeZoneRequest);
    }

    public RouteingNumber createRouteingNumber(String data) {
        return new RouteingNumberImpl(data);
    }

    public SubscriberInfo createSubscriberInfo(LocationInformation locationInformation, SubscriberState subscriberState,
            MAPExtensionContainer extensionContainer, LocationInformationGPRS locationInformationGPRS,
            PSSubscriberState psSubscriberState, IMEI imei, MSClassmark2 msClassmark2, GPRSMSClass gprsMSClass,
            MNPInfoRes mnpInfoRes) {
        return new SubscriberInfoImpl(locationInformation, subscriberState, extensionContainer, locationInformationGPRS,
                psSubscriberState, imei, msClassmark2, gprsMSClass, mnpInfoRes);
    }

    public UserCSGInformation createUserCSGInformation(CSGId csgId, MAPExtensionContainer extensionContainer,
            Integer accessMode, Integer cmi) {
        return new UserCSGInformationImpl(csgId, extensionContainer, accessMode, cmi);
    }

    public PSSubscriberState createPSSubscriberState(PSSubscriberStateChoice choice, NotReachableReason netDetNotReachable,
            ArrayList<PDPContextInfo> pdpContextInfoList) {
        return new PSSubscriberStateImpl(choice, netDetNotReachable, pdpContextInfoList);
    }

    public AddGeographicalInformation createAddGeographicalInformation(byte[] data) {
        return new AddGeographicalInformationImpl(data);
    }

    public AdditionalNumber createAdditionalNumberMscNumber(ISDNAddressString mSCNumber) {
        return new AdditionalNumberImpl(mSCNumber, null);
    }

    public AdditionalNumber createAdditionalNumberSgsnNumber(ISDNAddressString sGSNNumber) {
        return new AdditionalNumberImpl(null, sGSNNumber);
    }

    public AreaDefinition createAreaDefinition(ArrayList<Area> areaList) {
        return new AreaDefinitionImpl(areaList);
    }

    public AreaEventInfo createAreaEventInfo(AreaDefinition areaDefinition, OccurrenceInfo occurrenceInfo, Integer intervalTime) {
        return new AreaEventInfoImpl(areaDefinition, occurrenceInfo, intervalTime);
    }

    public AreaIdentification createAreaIdentification(byte[] data) {
        return new AreaIdentificationImpl(data);
    }

    public AreaIdentification createAreaIdentification(AreaType type, int mcc, int mnc, int lac, int Rac_CellId_UtranCellId)
            throws MAPException {
        return new AreaIdentificationImpl(type, mcc, mnc, lac, Rac_CellId_UtranCellId);
    }

    public Area createArea(AreaType areaType, AreaIdentification areaIdentification) {
        return new AreaImpl(areaType, areaIdentification);
    }

    public DeferredLocationEventType createDeferredLocationEventType(boolean msAvailable, boolean enteringIntoArea, boolean leavingFromArea,
                                                                     boolean beingInsideArea, boolean periodicLDR) {
        return new DeferredLocationEventTypeImpl(msAvailable, enteringIntoArea, leavingFromArea, beingInsideArea, periodicLDR);
    }

    public DeferredmtlrData createDeferredmtlrData(DeferredLocationEventType deferredLocationEventType,
            TerminationCause terminationCause, LCSLocationInfo lcsLocationInfo) {
        return new DeferredmtlrDataImpl(deferredLocationEventType, terminationCause, lcsLocationInfo);
    }

    public ExtGeographicalInformation createExtGeographicalInformation(byte[] data) {
        return new ExtGeographicalInformationImpl(data);
    }

    public GeranGANSSpositioningData createGeranGANSSpositioningData(byte[] data) {
        return new GeranGANSSpositioningDataImpl(data);
    }

    public LCSClientID createLCSClientID(LCSClientType lcsClientType, LCSClientExternalID lcsClientExternalID,
            LCSClientInternalID lcsClientInternalID, LCSClientName lcsClientName, AddressString lcsClientDialedByMS,
            APN lcsAPN, LCSRequestorID lcsRequestorID) {
        return new LCSClientIDImpl(lcsClientType, lcsClientExternalID, lcsClientInternalID, lcsClientName, lcsClientDialedByMS,
                lcsAPN, lcsRequestorID);
    }

    public LCSClientExternalID createLCSClientExternalID(ISDNAddressString externalAddress,
            MAPExtensionContainer extensionContainer) {
        return new LCSClientExternalIDImpl(externalAddress, extensionContainer);
    }

    public LCSClientName createLCSClientName(CBSDataCodingScheme dataCodingScheme, USSDString nameString,
            LCSFormatIndicator lcsFormatIndicator) {
        return new LCSClientNameImpl(dataCodingScheme, nameString, lcsFormatIndicator);
    }

    public LCSCodeword createLCSCodeword(CBSDataCodingScheme dataCodingScheme, USSDString lcsCodewordString) {
        return new LCSCodewordImpl(dataCodingScheme, lcsCodewordString);
    }

    public LCSLocationInfo createLCSLocationInfo(ISDNAddressString networkNodeNumber, LMSI lmsi,
            MAPExtensionContainer extensionContainer, boolean gprsNodeIndicator, AdditionalNumber additionalNumber,
            SupportedLCSCapabilitySets supportedLCSCapabilitySets, SupportedLCSCapabilitySets additionalLCSCapabilitySets,
            DiameterIdentity mmeName, DiameterIdentity aaaServerName) {
        return new LCSLocationInfoImpl(networkNodeNumber, lmsi, extensionContainer, gprsNodeIndicator, additionalNumber,
                supportedLCSCapabilitySets, additionalLCSCapabilitySets, mmeName, aaaServerName);
    }

    public LCSPrivacyCheck createLCSPrivacyCheck(PrivacyCheckRelatedAction callSessionUnrelated,
            PrivacyCheckRelatedAction callSessionRelated) {
        return new LCSPrivacyCheckImpl(callSessionUnrelated, callSessionRelated);
    }

    public LCSQoS createLCSQoS(Integer horizontalAccuracy, Integer verticalAccuracy, boolean verticalCoordinateRequest,
            ResponseTime responseTime, MAPExtensionContainer extensionContainer) {
        return new LCSQoSImpl(horizontalAccuracy, verticalAccuracy, verticalCoordinateRequest, responseTime, extensionContainer);
    }

    public LCSRequestorID createLCSRequestorID(CBSDataCodingScheme dataCodingScheme, USSDString requestorIDString,
            LCSFormatIndicator lcsFormatIndicator) {
        return new LCSRequestorIDImpl(dataCodingScheme, requestorIDString, lcsFormatIndicator);
    }

    public LocationType createLocationType(LocationEstimateType locationEstimateType,
            DeferredLocationEventType deferredLocationEventType) {
        return new LocationTypeImpl(locationEstimateType, deferredLocationEventType);
    }

    public PeriodicLDRInfo createPeriodicLDRInfo(int reportingAmount, int reportingInterval) {
        return new PeriodicLDRInfoImpl(reportingAmount, reportingInterval);
    }

    public PositioningDataInformation createPositioningDataInformation(byte[] data) {
        return new PositioningDataInformationImpl(data);
    }

    public ReportingPLMN createReportingPLMN(PlmnId plmnId, RANTechnology ranTechnology, boolean ranPeriodicLocationSupport) {
        return new ReportingPLMNImpl(plmnId, ranTechnology, ranPeriodicLocationSupport);
    }

    public ReportingPLMNList createReportingPLMNList(boolean plmnListPrioritized, ArrayList<ReportingPLMN> plmnList) {
        return new ReportingPLMNListImpl(plmnListPrioritized, plmnList);
    }

    public ResponseTime createResponseTime(ResponseTimeCategory responseTimeCategory) {
        return new ResponseTimeImpl(responseTimeCategory);
    }

    public ServingNodeAddress createServingNodeAddressMscNumber(ISDNAddressString mscNumber) {
        return new ServingNodeAddressImpl(mscNumber, true);
    }

    public ServingNodeAddress createServingNodeAddressSgsnNumber(ISDNAddressString sgsnNumber) {
        return new ServingNodeAddressImpl(sgsnNumber, false);
    }

    public ServingNodeAddress createServingNodeAddressMmeNumber(DiameterIdentity mmeNumber) {
        return new ServingNodeAddressImpl(mmeNumber);
    }

    public SLRArgExtensionContainer createSLRArgExtensionContainer(ArrayList<MAPPrivateExtension> privateExtensionList,
            SLRArgPCSExtensions slrArgPcsExtensions) {
        return new SLRArgExtensionContainerImpl(privateExtensionList, slrArgPcsExtensions);
    }

    public SLRArgPCSExtensions createSLRArgPCSExtensions(boolean naEsrkRequest) {
        return new SLRArgPCSExtensionsImpl(naEsrkRequest);
    }

    public SupportedGADShapes createSupportedGADShapes(boolean ellipsoidPoint, boolean ellipsoidPointWithUncertaintyCircle,
            boolean ellipsoidPointWithUncertaintyEllipse, boolean polygon, boolean ellipsoidPointWithAltitude,
            boolean ellipsoidPointWithAltitudeAndUncertaintyElipsoid, boolean ellipsoidArc) {
        return new SupportedGADShapesImpl(ellipsoidPoint, ellipsoidPointWithUncertaintyCircle,
                ellipsoidPointWithUncertaintyEllipse, polygon, ellipsoidPointWithAltitude,
                ellipsoidPointWithAltitudeAndUncertaintyElipsoid, ellipsoidArc);
    }

    public UtranGANSSpositioningData createUtranGANSSpositioningData(byte[] data) {
        return new UtranGANSSpositioningDataImpl(data);
    }

    public UtranPositioningDataInfo createUtranPositioningDataInfo(byte[] data) {
        return new UtranPositioningDataInfoImpl(data);
    }

    public VelocityEstimate createVelocityEstimate(byte[] data) {
        return new VelocityEstimateImpl(data);
    }

    @Override
    public RequestedEquipmentInfo createRequestedEquipmentInfo(boolean equipmentStatus, boolean bmuef) {
        return new RequestedEquipmentInfoImpl(equipmentStatus, bmuef);
    }

    @Override
    public UESBIIuA createUESBIIuA(BitSetStrictLength data) {
        return new UESBIIuAImpl(data);
    }

    @Override
    public UESBIIuB createUESBIIuB(BitSetStrictLength data) {
        return new UESBIIuBImpl(data);
    }

    @Override
    public UESBIIu createUESBIIu(UESBIIuA uesbiIuA, UESBIIuB uesbiIuB) {
        return new UESBIIuImpl(uesbiIuA, uesbiIuB);
    }

    public IMSIWithLMSI createServingNodeAddressMmeNumber(IMSI imsi, LMSI lmsi) {
        return new IMSIWithLMSIImpl(imsi, lmsi);
    }

    @Override
    public CamelRoutingInfo createCamelRoutingInfo(ForwardingData forwardingData,
            GmscCamelSubscriptionInfo gmscCamelSubscriptionInfo, MAPExtensionContainer extensionContainer) {
        return new CamelRoutingInfoImpl(forwardingData, gmscCamelSubscriptionInfo, extensionContainer);
    }

    @Override
    public GmscCamelSubscriptionInfo createGmscCamelSubscriptionInfo(TCSI tCsi, OCSI oCsi,
            MAPExtensionContainer extensionContainer, ArrayList<OBcsmCamelTdpCriteria> oBcsmCamelTDPCriteriaList,
            ArrayList<TBcsmCamelTdpCriteria> tBcsmCamelTdpCriteriaList, DCSI dCsi) {
        return new GmscCamelSubscriptionInfoImpl(tCsi, oCsi, extensionContainer, oBcsmCamelTDPCriteriaList,
                tBcsmCamelTdpCriteriaList, dCsi);
    }

    @Override
    public TCSI createTCSI(ArrayList<TBcsmCamelTDPData> tBcsmCamelTDPDataList, MAPExtensionContainer extensionContainer,
            Integer camelCapabilityHandling, boolean notificationToCSE, boolean csiActive) {
        return new TCSIImpl(tBcsmCamelTDPDataList, extensionContainer, camelCapabilityHandling, notificationToCSE, csiActive);
    }

    @Override
    public OCSI createOCSI(ArrayList<OBcsmCamelTDPData> oBcsmCamelTDPDataList, MAPExtensionContainer extensionContainer,
            Integer camelCapabilityHandling, boolean notificationToCSE, boolean csiActive) {
        return new OCSIImpl(oBcsmCamelTDPDataList, extensionContainer, camelCapabilityHandling, notificationToCSE, csiActive);
    }

    @Override
    public TBcsmCamelTDPData createTBcsmCamelTDPData(TBcsmTriggerDetectionPoint tBcsmTriggerDetectionPoint, long serviceKey,
            ISDNAddressString gsmSCFAddress, DefaultCallHandling defaultCallHandling, MAPExtensionContainer extensionContainer) {
        return new TBcsmCamelTDPDataImpl(tBcsmTriggerDetectionPoint, serviceKey, gsmSCFAddress, defaultCallHandling,
                extensionContainer);
    }

    @Override
    public OBcsmCamelTDPData createOBcsmCamelTDPData(OBcsmTriggerDetectionPoint oBcsmTriggerDetectionPoint, long serviceKey,
            ISDNAddressString gsmSCFAddress, DefaultCallHandling defaultCallHandling, MAPExtensionContainer extensionContainer) {
        return new OBcsmCamelTDPDataImpl(oBcsmTriggerDetectionPoint, serviceKey, gsmSCFAddress, defaultCallHandling,
                extensionContainer);
    }

    @Override
    public CamelInfo createCamelInfo(SupportedCamelPhases supportedCamelPhases, boolean suppressTCSI,
            MAPExtensionContainer extensionContainer, OfferedCamel4CSIs offeredCamel4CSIs) {
        return new CamelInfoImpl(supportedCamelPhases, suppressTCSI, extensionContainer, offeredCamel4CSIs);
    }

    @Override
    public CUGInterlock createCUGInterlock(byte[] data) {
        return new CUGInterlockImpl(data);
    }

    @Override
    public CUGCheckInfo createCUGCheckInfo(CUGInterlock cugInterlock, boolean cugOutgoingAccess,
            MAPExtensionContainer extensionContainer) {
        return new CUGCheckInfoImpl(cugInterlock, cugOutgoingAccess, extensionContainer);
    }

    @Override
    public PDPContext createPDPContext(int pdpContextId, PDPType pdpType, PDPAddress pdpAddress, QoSSubscribed qosSubscribed,
            boolean vplmnAddressAllowed, APN apn, MAPExtensionContainer extensionContainer, ExtQoSSubscribed extQoSSubscribed,
            ChargingCharacteristics chargingCharacteristics, Ext2QoSSubscribed ext2QoSSubscribed,
            Ext3QoSSubscribed ext3QoSSubscribed, Ext4QoSSubscribed ext4QoSSubscribed, APNOIReplacement apnoiReplacement,
            ExtPDPType extpdpType, PDPAddress extpdpAddress, SIPTOPermission sipToPermission, LIPAPermission lipaPermission) {
        return new PDPContextImpl(pdpContextId, pdpType, pdpAddress, qosSubscribed, vplmnAddressAllowed, apn,
                extensionContainer, extQoSSubscribed, chargingCharacteristics, ext2QoSSubscribed, ext3QoSSubscribed,
                ext4QoSSubscribed, apnoiReplacement, extpdpType, extpdpAddress, sipToPermission, lipaPermission);
    }

    @Override
    public APNOIReplacement createAPNOIReplacement(byte[] data) {
        return new APNOIReplacementImpl(data);
    }

    @Override
    public QoSSubscribed createQoSSubscribed(byte[] data) {
        return new QoSSubscribedImpl(data);
    }

    @Override
    public QoSSubscribed createQoSSubscribed(QoSSubscribed_ReliabilityClass reliabilityClass, QoSSubscribed_DelayClass delayClass,
            QoSSubscribed_PrecedenceClass precedenceClass, QoSSubscribed_PeakThroughput peakThroughput, QoSSubscribed_MeanThroughput meanThroughput) {
        return new QoSSubscribedImpl(reliabilityClass, delayClass, precedenceClass, peakThroughput, meanThroughput);
    }

    @Override
    public SSCode createSSCode(SupplementaryCodeValue value) {
        return new SSCodeImpl(value);
    }

    @Override
    public SSCode createSSCode(int data) {
        return new SSCodeImpl(data);
    }

    @Override
    public SSStatus createSSStatus(boolean qBit, boolean pBit, boolean rBit, boolean aBit) {
        return new SSStatusImpl(qBit, pBit, rBit, aBit);
    }

    @Override
    public BasicServiceCode createBasicServiceCode(TeleserviceCode teleservice) {
        return new BasicServiceCodeImpl(teleservice);
    }

    @Override
    public BasicServiceCode createBasicServiceCode(BearerServiceCode bearerService) {
        return new BasicServiceCodeImpl(bearerService);
    }

    @Override
    public GeographicalInformation createGeographicalInformation(double latitude, double longitude, double uncertainty)
            throws MAPException {
        return new GeographicalInformationImpl(TypeOfShape.EllipsoidPointWithUncertaintyCircle, latitude, longitude,
                uncertainty);
    }

    @Override
    public GeodeticInformation createGeodeticInformation(int screeningAndPresentationIndicators, double latitude,
            double longitude, double uncertainty, int confidence) throws MAPException {
        return new GeodeticInformationImpl(screeningAndPresentationIndicators, TypeOfShape.EllipsoidPointWithUncertaintyCircle,
                latitude, longitude, uncertainty, confidence);
    }

    @Override
    public ExtGeographicalInformation createExtGeographicalInformation_EllipsoidPointWithUncertaintyCircle(double latitude,
            double longitude, double uncertainty) throws MAPException {
        return new ExtGeographicalInformationImpl(TypeOfShape.EllipsoidPointWithUncertaintyCircle, latitude, longitude,
                uncertainty, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    }

    @Override
    public ExtGeographicalInformation createExtGeographicalInformation_EllipsoidPointWithUncertaintyEllipse(double latitude,
            double longitude, double uncertaintySemiMajorAxis, double uncertaintySemiMinorAxis, double angleOfMajorAxis,
            int confidence) throws MAPException {
        return new ExtGeographicalInformationImpl(TypeOfShape.EllipsoidPointWithUncertaintyEllipse, latitude, longitude, 0,
                uncertaintySemiMajorAxis, uncertaintySemiMinorAxis, angleOfMajorAxis, confidence, 0, 0, 0, 0, 0, 0);
    }

    @Override
    public ExtGeographicalInformation createExtGeographicalInformation_EllipsoidPointWithAltitudeAndUncertaintyEllipsoid(
            double latitude, double longitude, double uncertaintySemiMajorAxis, double uncertaintySemiMinorAxis,
            double angleOfMajorAxis, int confidence, int altitude, double uncertaintyAltitude) throws MAPException {
        return new ExtGeographicalInformationImpl(TypeOfShape.EllipsoidPointWithAltitudeAndUncertaintyEllipsoid, latitude,
                longitude, 0, uncertaintySemiMajorAxis, uncertaintySemiMinorAxis, angleOfMajorAxis, confidence, altitude,
                uncertaintyAltitude, 0, 0, 0, 0);
    }

    @Override
    public ExtGeographicalInformation createExtGeographicalInformation_EllipsoidArc(double latitude, double longitude,
            int innerRadius, double uncertaintyRadius, double offsetAngle, double includedAngle, int confidence)
            throws MAPException {
        return new ExtGeographicalInformationImpl(TypeOfShape.EllipsoidArc, latitude, longitude, 0, 0, 0, 0, confidence, 0, 0,
                innerRadius, uncertaintyRadius, offsetAngle, includedAngle);
    }

    @Override
    public ExtGeographicalInformation createExtGeographicalInformation_EllipsoidPoint(double latitude, double longitude)
            throws MAPException {
        return new ExtGeographicalInformationImpl(TypeOfShape.EllipsoidPoint, latitude, longitude, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0);
    }

    @Override
    public AddGeographicalInformation createAddGeographicalInformation_EllipsoidPointWithUncertaintyCircle(double latitude,
            double longitude, double uncertainty) throws MAPException {
        return new AddGeographicalInformationImpl(TypeOfShape.EllipsoidPointWithUncertaintyCircle, latitude, longitude,
                uncertainty, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    }

    @Override
    public AddGeographicalInformation createAddGeographicalInformation_EllipsoidPointWithUncertaintyEllipse(double latitude,
            double longitude, double uncertaintySemiMajorAxis, double uncertaintySemiMinorAxis, double angleOfMajorAxis,
            int confidence) throws MAPException {
        return new AddGeographicalInformationImpl(TypeOfShape.EllipsoidPointWithUncertaintyEllipse, latitude, longitude, 0,
                uncertaintySemiMajorAxis, uncertaintySemiMinorAxis, angleOfMajorAxis, confidence, 0, 0, 0, 0, 0, 0);
    }

    @Override
    public ExtGeographicalInformation createExtGeographicalInformation_Polygon(int numberOfPoints, Object polygon) throws MAPException {
        // TODO
        return new AddGeographicalInformationImpl(TypeOfShape.Polygon, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    }

    @Override
    public AddGeographicalInformation createAddGeographicalInformation_EllipsoidPointWithAltitudeAndUncertaintyEllipsoid(
            double latitude, double longitude, double uncertaintySemiMajorAxis, double uncertaintySemiMinorAxis,
            double angleOfMajorAxis, int confidence, int altitude, double uncertaintyAltitude) throws MAPException {
        return new AddGeographicalInformationImpl(TypeOfShape.EllipsoidPointWithAltitudeAndUncertaintyEllipsoid, latitude,
                longitude, 0, uncertaintySemiMajorAxis, uncertaintySemiMinorAxis, angleOfMajorAxis, confidence, altitude,
                uncertaintyAltitude, 0, 0, 0, 0);
    }

    @Override
    public AddGeographicalInformation createAddGeographicalInformation_EllipsoidArc(double latitude, double longitude,
            int innerRadius, double uncertaintyRadius, double offsetAngle, double includedAngle, int confidence)
            throws MAPException {
        return new AddGeographicalInformationImpl(TypeOfShape.EllipsoidArc, latitude, longitude, 0, 0, 0, 0, confidence, 0, 0,
                innerRadius, uncertaintyRadius, offsetAngle, includedAngle);
    }

    @Override
    public AddGeographicalInformation createAddGeographicalInformation_EllipsoidPoint(double latitude, double longitude)
            throws MAPException {
        return new AddGeographicalInformationImpl(TypeOfShape.EllipsoidPoint, latitude, longitude, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0);
    }

    @Override
    public VelocityEstimate createVelocityEstimate_HorizontalVelocity(int horizontalSpeed, int bearing) throws MAPException {
        return new VelocityEstimateImpl(VelocityType.HorizontalVelocity, horizontalSpeed, bearing, 0, 0, 0);
    }

    @Override
    public VelocityEstimate createVelocityEstimate_HorizontalWithVerticalVelocity(int horizontalSpeed, int bearing,
            int verticalSpeed) throws MAPException {
        return new VelocityEstimateImpl(VelocityType.HorizontalWithVerticalVelocity, horizontalSpeed, bearing, verticalSpeed,
                0, 0);
    }

    @Override
    public VelocityEstimate createVelocityEstimate_HorizontalVelocityWithUncertainty(int horizontalSpeed, int bearing,
            int uncertaintyHorizontalSpeed) throws MAPException {
        return new VelocityEstimateImpl(VelocityType.HorizontalVelocityWithUncertainty, horizontalSpeed, bearing, 0,
                uncertaintyHorizontalSpeed, 0);
    }

    @Override
    public VelocityEstimate createVelocityEstimate_HorizontalWithVerticalVelocityAndUncertainty(int horizontalSpeed,
            int bearing, int verticalSpeed, int uncertaintyHorizontalSpeed, int uncertaintyVerticalSpeed) throws MAPException {
        return new VelocityEstimateImpl(VelocityType.HorizontalWithVerticalVelocityAndUncertainty, horizontalSpeed, bearing,
                verticalSpeed, uncertaintyHorizontalSpeed, uncertaintyVerticalSpeed);
    }

    @Override
    public CUGFeature createCUGFeature(ExtBasicServiceCode basicService, Integer preferentialCugIndicator,
            InterCUGRestrictions interCugRestrictions, MAPExtensionContainer extensionContainer) {
        return new CUGFeatureImpl(basicService, preferentialCugIndicator, interCugRestrictions, extensionContainer);
    }

    @Override
    public CUGInfo createCUGInfo(ArrayList<CUGSubscription> cugSubscriptionList, ArrayList<CUGFeature> cugFeatureList,
            MAPExtensionContainer extensionContainer) {
        return new CUGInfoImpl(cugSubscriptionList, cugFeatureList, extensionContainer);
    }

    @Override
    public CUGSubscription createCUGSubscription(int cugIndex, CUGInterlock cugInterlock, IntraCUGOptions intraCugOptions,
            ArrayList<ExtBasicServiceCode> basicService, MAPExtensionContainer extensionContainer) {
        return new CUGSubscriptionImpl(cugIndex, cugInterlock, intraCugOptions, basicService, extensionContainer);
    }

    @Override
    public EMLPPInfo createEMLPPInfo(int maximumentitledPriority, int defaultPriority, MAPExtensionContainer extensionContainer) {
        return new EMLPPInfoImpl(maximumentitledPriority, defaultPriority, extensionContainer);
    }

    @Override
    public ExtCallBarInfo createExtCallBarInfo(SSCode ssCode, ArrayList<ExtCallBarringFeature> callBarringFeatureList,
            MAPExtensionContainer extensionContainer) {
        return new ExtCallBarInfoImpl(ssCode, callBarringFeatureList, extensionContainer);
    }

    @Override
    public ExtCallBarringFeature createExtCallBarringFeature(ExtBasicServiceCode basicService, ExtSSStatus ssStatus,
            MAPExtensionContainer extensionContainer) {
        return new ExtCallBarringFeatureImpl(basicService, ssStatus, extensionContainer);
    }

    @Override
    public ExtForwFeature createExtForwFeature(ExtBasicServiceCode basicService, ExtSSStatus ssStatus,
            ISDNAddressString forwardedToNumber, ISDNSubaddressString forwardedToSubaddress, ExtForwOptions forwardingOptions,
            Integer noReplyConditionTime, MAPExtensionContainer extensionContainer, FTNAddressString longForwardedToNumber) {
        return new ExtForwFeatureImpl(basicService, ssStatus, forwardedToNumber, forwardedToSubaddress, forwardingOptions,
                noReplyConditionTime, extensionContainer, longForwardedToNumber);
    }

    @Override
    public ExtForwInfo createExtForwInfo(SSCode ssCode, ArrayList<ExtForwFeature> forwardingFeatureList,
            MAPExtensionContainer extensionContainer) {
        return new ExtForwInfoImpl(ssCode, forwardingFeatureList, extensionContainer);
    }

    @Override
    public ExtForwOptions createExtForwOptions(boolean notificationToForwardingParty, boolean redirectingPresentation,
            boolean notificationToCallingParty, ExtForwOptionsForwardingReason extForwOptionsForwardingReason) {
        return new ExtForwOptionsImpl(notificationToForwardingParty, redirectingPresentation, notificationToCallingParty,
                extForwOptionsForwardingReason);
    }

    @Override
    public ExtForwOptions createExtForwOptions(byte[] data) {
        return new ExtForwOptionsImpl(data);
    }

    @Override
    public ExtSSData createExtSSData(SSCode ssCode, ExtSSStatus ssStatus, SSSubscriptionOption ssSubscriptionOption,
            ArrayList<ExtBasicServiceCode> basicServiceGroupList, MAPExtensionContainer extensionContainer) {
        return new ExtSSDataImpl(ssCode, ssStatus, ssSubscriptionOption, basicServiceGroupList, extensionContainer);
    }

    @Override
    public ExtSSInfo createExtSSInfo(ExtForwInfo forwardingInfo) {
        return new ExtSSInfoImpl(forwardingInfo);
    }

    @Override
    public ExtSSInfo createExtSSInfo(ExtCallBarInfo callBarringInfo) {
        return new ExtSSInfoImpl(callBarringInfo);
    }

    @Override
    public ExtSSInfo createExtSSInfo(CUGInfo cugInfo) {
        return new ExtSSInfoImpl(cugInfo);
    }

    @Override
    public ExtSSInfo createExtSSInfo(ExtSSData ssData) {
        return new ExtSSInfoImpl(ssData);
    }

    @Override
    public ExtSSInfo createExtSSInfo(EMLPPInfo emlppInfo) {
        return new ExtSSInfoImpl(emlppInfo);
    }

    @Override
    public ExtSSStatus createExtSSStatus(boolean bitQ, boolean bitP, boolean bitR, boolean bitA) {
        return new ExtSSStatusImpl(bitQ, bitP, bitR, bitA);
    }

    @Override
    public ExtSSStatus createExtSSStatus(byte[] data) {
        return new ExtSSStatusImpl(data);
    }

    @Override
    public GPRSSubscriptionData createGPRSSubscriptionData(boolean completeDataListIncluded,
            ArrayList<PDPContext> gprsDataList, MAPExtensionContainer extensionContainer, APNOIReplacement apnOiReplacement) {
        return new GPRSSubscriptionDataImpl(completeDataListIncluded, gprsDataList, extensionContainer, apnOiReplacement);
    }

    @Override
    public SSSubscriptionOption createSSSubscriptionOption(CliRestrictionOption cliRestrictionOption) {
        return new SSSubscriptionOptionImpl(cliRestrictionOption);
    }

    @Override
    public SSSubscriptionOption createSSSubscriptionOption(OverrideCategory overrideCategory) {
        return new SSSubscriptionOptionImpl(overrideCategory);
    }

    @Override
    public InterCUGRestrictions createInterCUGRestrictions(InterCUGRestrictionsValue val) {
        return new InterCUGRestrictionsImpl(val);
    }

    @Override
    public InterCUGRestrictions createInterCUGRestrictions(int data) {
        return new InterCUGRestrictionsImpl(data);
    }

    @Override
    public ZoneCode createZoneCode(int value) {
        return new ZoneCodeImpl(value);
    }

    @Override
    public ZoneCode createZoneCode(byte[] data) {
        return new ZoneCodeImpl(data);
    }

    @Override
    public AgeIndicator createAgeIndicator(byte[] data) {
        return new AgeIndicatorImpl(data);
    }

    @Override
    public CSAllocationRetentionPriority createCSAllocationRetentionPriority(int data) {
        return new CSAllocationRetentionPriorityImpl(data);
    }

    @Override
    public SupportedFeatures createSupportedFeatures(boolean odbAllApn, boolean odbHPLMNApn, boolean odbVPLMNApn,
            boolean odbAllOg, boolean odbAllInternationalOg, boolean odbAllIntOgNotToHPLMNCountry, boolean odbAllInterzonalOg,
            boolean odbAllInterzonalOgNotToHPLMNCountry, boolean odbAllInterzonalOgandInternatOgNotToHPLMNCountry,
            boolean regSub, boolean trace, boolean lcsAllPrivExcep, boolean lcsUniversal, boolean lcsCallSessionRelated,
            boolean lcsCallSessionUnrelated, boolean lcsPLMNOperator, boolean lcsServiceType, boolean lcsAllMOLRSS,
            boolean lcsBasicSelfLocation, boolean lcsAutonomousSelfLocation, boolean lcsTransferToThirdParty, boolean smMoPp,
            boolean barringOutgoingCalls, boolean baoc, boolean boic, boolean boicExHC) {
        return new SupportedFeaturesImpl(odbAllApn, odbHPLMNApn, odbVPLMNApn, odbAllOg, odbAllInternationalOg,
                odbAllIntOgNotToHPLMNCountry, odbAllInterzonalOg, odbAllInterzonalOgNotToHPLMNCountry,
                odbAllInterzonalOgandInternatOgNotToHPLMNCountry, regSub, trace, lcsAllPrivExcep, lcsUniversal,
                lcsCallSessionRelated, lcsCallSessionUnrelated, lcsPLMNOperator, lcsServiceType, lcsAllMOLRSS,
                lcsBasicSelfLocation, lcsAutonomousSelfLocation, lcsTransferToThirdParty, smMoPp, barringOutgoingCalls, baoc,
                boic, boicExHC);
    }

    @Override
    public AccessRestrictionData createAccessRestrictionData(boolean utranNotAllowed, boolean geranNotAllowed,
            boolean ganNotAllowed, boolean iHspaEvolutionNotAllowed, boolean eUtranNotAllowed,
            boolean hoToNon3GPPAccessNotAllowed) {
        return new AccessRestrictionDataImpl(utranNotAllowed, geranNotAllowed, ganNotAllowed, iHspaEvolutionNotAllowed,
                eUtranNotAllowed, hoToNon3GPPAccessNotAllowed);
    }

    @Override
    public AdditionalInfo createAdditionalInfo(BitSetStrictLength data) {
        return new AdditionalInfoImpl(data);
    }

    @Override
    public AdditionalSubscriptions createAdditionalSubscriptions(boolean privilegedUplinkRequest,
            boolean emergencyUplinkRequest, boolean emergencyReset) {
        return new AdditionalSubscriptionsImpl(privilegedUplinkRequest, emergencyUplinkRequest, emergencyReset);
    }

    @Override
    public AMBR createAMBR(int maxRequestedBandwidthUL, int maxRequestedBandwidthDL, MAPExtensionContainer extensionContainer) {
        return new AMBRImpl(maxRequestedBandwidthUL, maxRequestedBandwidthDL, extensionContainer);
    }

    @Override
    public APNConfiguration createAPNConfiguration(int contextId, PDNType pDNType, PDPAddress servedPartyIPIPv4Address,
            APN apn, EPSQoSSubscribed ePSQoSSubscribed, PDNGWIdentity pdnGwIdentity, PDNGWAllocationType pdnGwAllocationType,
            boolean vplmnAddressAllowed, ChargingCharacteristics chargingCharacteristics, AMBR ambr,
            ArrayList<SpecificAPNInfo> specificAPNInfoList, MAPExtensionContainer extensionContainer,
            PDPAddress servedPartyIPIPv6Address, APNOIReplacement apnOiReplacement, SIPTOPermission siptoPermission,
            LIPAPermission lipaPermission) {
        return new APNConfigurationImpl(contextId, pDNType, servedPartyIPIPv4Address, apn, ePSQoSSubscribed, pdnGwIdentity,
                pdnGwAllocationType, vplmnAddressAllowed, chargingCharacteristics, ambr, specificAPNInfoList,
                extensionContainer, servedPartyIPIPv6Address, apnOiReplacement, siptoPermission, lipaPermission);
    }

    @Override
    public APNConfigurationProfile createAPNConfigurationProfile(int defaultContext, boolean completeDataListIncluded,
            ArrayList<APNConfiguration> ePSDataList, MAPExtensionContainer extensionContainer) {
        return new APNConfigurationProfileImpl(defaultContext, completeDataListIncluded, ePSDataList, extensionContainer);
    }

    @Override
    public CSGSubscriptionData createCSGSubscriptionData(CSGId csgId, Time expirationDate,
            MAPExtensionContainer extensionContainer, ArrayList<APN> lipaAllowedAPNList) {
        return new CSGSubscriptionDataImpl(csgId, expirationDate, extensionContainer, lipaAllowedAPNList);
    }

    @Override
    public DCSI createDCSI(ArrayList<DPAnalysedInfoCriterium> dpAnalysedInfoCriteriaList, Integer camelCapabilityHandling,
            MAPExtensionContainer extensionContainer, boolean notificationToCSE, boolean csiActive) {
        return new DCSIImpl(dpAnalysedInfoCriteriaList, camelCapabilityHandling, extensionContainer, notificationToCSE,
                csiActive);
    }

    @Override
    public DestinationNumberCriteria createDestinationNumberCriteria(MatchType matchType,
            ArrayList<ISDNAddressString> destinationNumberList, ArrayList<Integer> destinationNumberLengthList) {
        return new DestinationNumberCriteriaImpl(matchType, destinationNumberList, destinationNumberLengthList);
    }

    @Override
    public DPAnalysedInfoCriterium createDPAnalysedInfoCriterium(ISDNAddressString dialledNumber, long serviceKey,
            ISDNAddressString gsmSCFAddress, DefaultCallHandling defaultCallHandling, MAPExtensionContainer extensionContainer) {
        return new DPAnalysedInfoCriteriumImpl(dialledNumber, serviceKey, gsmSCFAddress, defaultCallHandling,
                extensionContainer);
    }

    @Override
    public EPSQoSSubscribed createEPSQoSSubscribed(QoSClassIdentifier qoSClassIdentifier,
            AllocationRetentionPriority allocationRetentionPriority, MAPExtensionContainer extensionContainer) {
        return new EPSQoSSubscribedImpl(qoSClassIdentifier, allocationRetentionPriority, extensionContainer);
    }

    @Override
    public EPSSubscriptionData createEPSSubscriptionData(APNOIReplacement apnOiReplacement, Integer rfspId, AMBR ambr,
            APNConfigurationProfile apnConfigurationProfile, ISDNAddressString stnSr, MAPExtensionContainer extensionContainer,
            boolean mpsCSPriority, boolean mpsEPSPriority) {
        return new EPSSubscriptionDataImpl(apnOiReplacement, rfspId, ambr, apnConfigurationProfile, stnSr, extensionContainer,
                mpsCSPriority, mpsEPSPriority);
    }

    @Override
    public ExternalClient createExternalClient(LCSClientExternalID clientIdentity, GMLCRestriction gmlcRestriction,
            NotificationToMSUser notificationToMSUser, MAPExtensionContainer extensionContainer) {
        return new ExternalClientImpl(clientIdentity, gmlcRestriction, notificationToMSUser, extensionContainer);
    }

    @Override
    public FQDN createFQDN(byte[] data) {
        return new FQDNImpl(data);
    }

    @Override
    public GPRSCamelTDPData createGPRSCamelTDPData(GPRSTriggerDetectionPoint gprsTriggerDetectionPoint, long serviceKey,
            ISDNAddressString gsmSCFAddress, DefaultGPRSHandling defaultSessionHandling,
            MAPExtensionContainer extensionContainer) {
        return new GPRSCamelTDPDataImpl(gprsTriggerDetectionPoint, serviceKey, gsmSCFAddress, defaultSessionHandling,
                extensionContainer);
    }

    @Override
    public GPRSCSI createGPRSCSI(ArrayList<GPRSCamelTDPData> gprsCamelTDPDataList, Integer camelCapabilityHandling,
            MAPExtensionContainer extensionContainer, boolean notificationToCSE, boolean csiActive) {
        return new GPRSCSIImpl(gprsCamelTDPDataList, camelCapabilityHandling, extensionContainer, notificationToCSE, csiActive);
    }

    @Override
    public LCSInformation createLCSInformation(ArrayList<ISDNAddressString> gmlcList,
            ArrayList<LCSPrivacyClass> lcsPrivacyExceptionList, ArrayList<MOLRClass> molrList,
            ArrayList<LCSPrivacyClass> addLcsPrivacyExceptionList) {
        return new LCSInformationImpl(gmlcList, lcsPrivacyExceptionList, molrList, addLcsPrivacyExceptionList);
    }

    @Override
    public LCSPrivacyClass createLCSPrivacyClass(SSCode ssCode, ExtSSStatus ssStatus,
            NotificationToMSUser notificationToMSUser, ArrayList<ExternalClient> externalClientList,
            ArrayList<LCSClientInternalID> plmnClientList, MAPExtensionContainer extensionContainer,
            ArrayList<ExternalClient> extExternalClientList, ArrayList<ServiceType> serviceTypeList) {
        return new LCSPrivacyClassImpl(ssCode, ssStatus, notificationToMSUser, externalClientList, plmnClientList,
                extensionContainer, extExternalClientList, serviceTypeList);
    }

    @Override
    public LSAData createLSAData(LSAIdentity lsaIdentity, LSAAttributes lsaAttributes, boolean lsaActiveModeIndicator,
            MAPExtensionContainer extensionContainer) {
        return new LSADataImpl(lsaIdentity, lsaAttributes, lsaActiveModeIndicator, extensionContainer);
    }

    @Override
    public LSAInformation createLSAInformation(boolean completeDataListIncluded, LSAOnlyAccessIndicator lsaOnlyAccessIndicator,
            ArrayList<LSAData> lsaDataList, MAPExtensionContainer extensionContainer) {
        return new LSAInformationImpl(completeDataListIncluded, lsaOnlyAccessIndicator, lsaDataList, extensionContainer);
    }

    @Override
    public MCSI createMCSI(ArrayList<MMCode> mobilityTriggers, long serviceKey, ISDNAddressString gsmSCFAddress,
            MAPExtensionContainer extensionContainer, boolean notificationToCSE, boolean csiActive) {
        return new MCSIImpl(mobilityTriggers, serviceKey, gsmSCFAddress, extensionContainer, notificationToCSE, csiActive);
    }

    @Override
    public MCSSInfo createMCSSInfo(SSCode ssCode, ExtSSStatus ssStatus, int nbrSB, int nbrUser,
            MAPExtensionContainer extensionContainer) {
        return new MCSSInfoImpl(ssCode, ssStatus, nbrSB, nbrUser, extensionContainer);
    }

    @Override
    public MGCSI createMGCSI(ArrayList<MMCode> mobilityTriggers, long serviceKey, ISDNAddressString gsmSCFAddress,
            MAPExtensionContainer extensionContainer, boolean notificationToCSE, boolean csiActive) {
        return new MGCSIImpl(mobilityTriggers, serviceKey, gsmSCFAddress, extensionContainer, notificationToCSE, csiActive);
    }

    @Override
    public MMCode createMMCode(MMCodeValue value) {
        return new MMCodeImpl(value);
    }

    @Override
    public MOLRClass createMOLRClass(SSCode ssCode, ExtSSStatus ssStatus, MAPExtensionContainer extensionContainer) {
        return new MOLRClassImpl(ssCode, ssStatus, extensionContainer);
    }

    @Override
    public MTsmsCAMELTDPCriteria createMTsmsCAMELTDPCriteria(SMSTriggerDetectionPoint smsTriggerDetectionPoint,
            ArrayList<MTSMSTPDUType> tPDUTypeCriterion) {
        return new MTsmsCAMELTDPCriteriaImpl(smsTriggerDetectionPoint, tPDUTypeCriterion);
    }

    @Override
    public OBcsmCamelTdpCriteria createOBcsmCamelTdpCriteria(OBcsmTriggerDetectionPoint oBcsmTriggerDetectionPoint,
            DestinationNumberCriteria destinationNumberCriteria, ArrayList<ExtBasicServiceCode> basicServiceCriteria,
            CallTypeCriteria callTypeCriteria, ArrayList<CauseValue> oCauseValueCriteria,
            MAPExtensionContainer extensionContainer) {
        return new OBcsmCamelTdpCriteriaImpl(oBcsmTriggerDetectionPoint, destinationNumberCriteria, basicServiceCriteria,
                callTypeCriteria, oCauseValueCriteria, extensionContainer);
    }

    @Override
    public ODBData createODBData(ODBGeneralData oDBGeneralData, ODBHPLMNData odbHplmnData,
            MAPExtensionContainer extensionContainer) {
        return new ODBDataImpl(oDBGeneralData, odbHplmnData, extensionContainer);
    }

    @Override
    public ODBGeneralData createODBGeneralData(boolean allOGCallsBarred, boolean internationalOGCallsBarred,
            boolean internationalOGCallsNotToHPLMNCountryBarred, boolean interzonalOGCallsBarred,
            boolean interzonalOGCallsNotToHPLMNCountryBarred,
            boolean interzonalOGCallsAndInternationalOGCallsNotToHPLMNCountryBarred,
            boolean premiumRateInformationOGCallsBarred, boolean premiumRateEntertainementOGCallsBarred,
            boolean ssAccessBarred, boolean allECTBarred, boolean chargeableECTBarred, boolean internationalECTBarred,
            boolean interzonalECTBarred, boolean doublyChargeableECTBarred, boolean multipleECTBarred,
            boolean allPacketOrientedServicesBarred, boolean roamerAccessToHPLMNAPBarred, boolean roamerAccessToVPLMNAPBarred,
            boolean roamingOutsidePLMNOGCallsBarred, boolean allICCallsBarred, boolean roamingOutsidePLMNICCallsBarred,
            boolean roamingOutsidePLMNICountryICCallsBarred, boolean roamingOutsidePLMNBarred,
            boolean roamingOutsidePLMNCountryBarred, boolean registrationAllCFBarred, boolean registrationCFNotToHPLMNBarred,
            boolean registrationInterzonalCFBarred, boolean registrationInterzonalCFNotToHPLMNBarred,
            boolean registrationInternationalCFBarred) {
        return new ODBGeneralDataImpl(allOGCallsBarred, internationalOGCallsBarred,
                internationalOGCallsNotToHPLMNCountryBarred, interzonalOGCallsBarred, interzonalOGCallsNotToHPLMNCountryBarred,
                interzonalOGCallsAndInternationalOGCallsNotToHPLMNCountryBarred, premiumRateInformationOGCallsBarred,
                premiumRateEntertainementOGCallsBarred, ssAccessBarred, allECTBarred, chargeableECTBarred,
                internationalECTBarred, interzonalECTBarred, doublyChargeableECTBarred, multipleECTBarred,
                allPacketOrientedServicesBarred, roamerAccessToHPLMNAPBarred, roamerAccessToVPLMNAPBarred,
                roamingOutsidePLMNOGCallsBarred, allICCallsBarred, roamingOutsidePLMNICCallsBarred,
                roamingOutsidePLMNICountryICCallsBarred, roamingOutsidePLMNBarred, roamingOutsidePLMNCountryBarred,
                registrationAllCFBarred, registrationCFNotToHPLMNBarred, registrationInterzonalCFBarred,
                registrationInterzonalCFNotToHPLMNBarred, registrationInternationalCFBarred);
    }

    @Override
    public ODBHPLMNData createODBHPLMNData(boolean plmnSpecificBarringType1, boolean plmnSpecificBarringType2,
            boolean plmnSpecificBarringType3, boolean plmnSpecificBarringType4) {
        return new ODBHPLMNDataImpl(plmnSpecificBarringType1, plmnSpecificBarringType2, plmnSpecificBarringType3,
                plmnSpecificBarringType4);
    }

    @Override
    public PDNGWIdentity createPDNGWIdentity(PDPAddress pdnGwIpv4Address, PDPAddress pdnGwIpv6Address, FQDN pdnGwName,
            MAPExtensionContainer extensionContainer) {
        return new PDNGWIdentityImpl(pdnGwIpv4Address, pdnGwIpv6Address, pdnGwName, extensionContainer);
    }

    @Override
    public PDNType createPDNType(PDNTypeValue value) {
        return new PDNTypeImpl(value);
    }

    @Override
    public PDNType createPDNType(int data) {
        return new PDNTypeImpl(data);
    }

    @Override
    public ServiceType createServiceType(int serviceTypeIdentity, GMLCRestriction gmlcRestriction,
            NotificationToMSUser notificationToMSUser, MAPExtensionContainer extensionContainer) {
        return new ServiceTypeImpl(serviceTypeIdentity, gmlcRestriction, notificationToMSUser, extensionContainer);
    }

    @Override
    public SGSNCAMELSubscriptionInfo createSGSNCAMELSubscriptionInfo(GPRSCSI gprsCsi, SMSCSI moSmsCsi,
            MAPExtensionContainer extensionContainer, SMSCSI mtSmsCsi,
            ArrayList<MTsmsCAMELTDPCriteria> mtSmsCamelTdpCriteriaList, MGCSI mgCsi) {
        return new SGSNCAMELSubscriptionInfoImpl(gprsCsi, moSmsCsi, extensionContainer, mtSmsCsi, mtSmsCamelTdpCriteriaList,
                mgCsi);
    }

    @Override
    public SMSCAMELTDPData createSMSCAMELTDPData(SMSTriggerDetectionPoint smsTriggerDetectionPoint, long serviceKey,
            ISDNAddressString gsmSCFAddress, DefaultSMSHandling defaultSMSHandling, MAPExtensionContainer extensionContainer) {
        return new SMSCAMELTDPDataImpl(smsTriggerDetectionPoint, serviceKey, gsmSCFAddress, defaultSMSHandling,
                extensionContainer);
    }

    @Override
    public SMSCSI createSMSCSI(ArrayList<SMSCAMELTDPData> smsCamelTdpDataList, Integer camelCapabilityHandling,
            MAPExtensionContainer extensionContainer, boolean notificationToCSE, boolean csiActive) {
        return new SMSCSIImpl(smsCamelTdpDataList, camelCapabilityHandling, extensionContainer, notificationToCSE, csiActive);
    }

    @Override
    public SpecificAPNInfo createSpecificAPNInfo(APN apn, PDNGWIdentity pdnGwIdentity, MAPExtensionContainer extensionContainer) {
        return new SpecificAPNInfoImpl(apn, pdnGwIdentity, extensionContainer);
    }

    @Override
    public SSCamelData createSSCamelData(ArrayList<SSCode> ssEventList, ISDNAddressString gsmSCFAddress,
            MAPExtensionContainer extensionContainer) {
        return new SSCamelDataImpl(ssEventList, gsmSCFAddress, extensionContainer);
    }

    @Override
    public SSCSI createSSCSI(SSCamelData ssCamelData, MAPExtensionContainer extensionContainer, boolean notificationToCSE,
            boolean csiActive) {
        return new SSCSIImpl(ssCamelData, extensionContainer, notificationToCSE, csiActive);
    }

    @Override
    public TBcsmCamelTdpCriteria createTBcsmCamelTdpCriteria(TBcsmTriggerDetectionPoint tBcsmTriggerDetectionPoint,
            ArrayList<ExtBasicServiceCode> basicServiceCriteria, ArrayList<CauseValue> tCauseValueCriteria) {
        return new TBcsmCamelTdpCriteriaImpl(tBcsmTriggerDetectionPoint, basicServiceCriteria, tCauseValueCriteria);
    }

    @Override
    public VlrCamelSubscriptionInfo createVlrCamelSubscriptionInfo(OCSI oCsi, MAPExtensionContainer extensionContainer,
            SSCSI ssCsi, ArrayList<OBcsmCamelTdpCriteria> oBcsmCamelTDPCriteriaList, boolean tifCsi, MCSI mCsi, SMSCSI smsCsi,
            TCSI vtCsi, ArrayList<TBcsmCamelTdpCriteria> tBcsmCamelTdpCriteriaList, DCSI dCsi, SMSCSI mtSmsCSI,
            ArrayList<MTsmsCAMELTDPCriteria> mtSmsCamelTdpCriteriaList) {
        return new VlrCamelSubscriptionInfoImpl(oCsi, extensionContainer, ssCsi, oBcsmCamelTDPCriteriaList, tifCsi, mCsi,
                smsCsi, vtCsi, tBcsmCamelTdpCriteriaList, dCsi, mtSmsCSI, mtSmsCamelTdpCriteriaList);
    }

    @Override
    public VoiceBroadcastData createVoiceBroadcastData(GroupId groupId, boolean broadcastInitEntitlement,
            MAPExtensionContainer extensionContainer, LongGroupId longGroupId) {
        return new VoiceBroadcastDataImpl(groupId, broadcastInitEntitlement, extensionContainer, longGroupId);
    }

    @Override
    public VoiceGroupCallData createVoiceGroupCallData(GroupId groupId, MAPExtensionContainer extensionContainer,
            AdditionalSubscriptions additionalSubscriptions, AdditionalInfo additionalInfo, LongGroupId longGroupId) {
        return new VoiceGroupCallDataImpl(groupId, extensionContainer, additionalSubscriptions, additionalInfo, longGroupId);
    }

    @Override
    public ISDNSubaddressString createISDNSubaddressString(byte[] data) {
        return new ISDNSubaddressStringImpl(data);
    }

    @Override
    public CauseValue createCauseValue(CauseValueCodeValue value) {
        return new CauseValueImpl(value);
    }

    @Override
    public CauseValue createCauseValue(int data) {
        return new CauseValueImpl(data);
    }

    @Override
    public GroupId createGroupId(String data) {
        return new GroupIdImpl(data);
    }

    @Override
    public LongGroupId createLongGroupId(String data) {
        return new LongGroupIdImpl(data);
    }

    @Override
    public LSAAttributes createLSAAttributes(LSAIdentificationPriorityValue value, boolean preferentialAccessAvailable,
            boolean activeModeSupportAvailable) {
        return new LSAAttributesImpl(value, preferentialAccessAvailable, activeModeSupportAvailable);
    }

    @Override
    public LSAAttributes createLSAAttributes(int data) {
        return new LSAAttributesImpl(data);
    }

    @Override
    public Time createTime(int year, int month, int day, int hour, int minute, int second) {
        return new TimeImpl(year, month, day, hour, minute, second);
    }

    @Override
    public Time createTime(byte[] data) {
        return new TimeImpl(data);
    }

    @Override
    public NAEACIC createNAEACIC(String carrierCode, NetworkIdentificationPlanValue networkIdentificationPlanValue,
            NetworkIdentificationTypeValue networkIdentificationTypeValue) throws MAPException {
        return new NAEACICImpl(carrierCode, networkIdentificationPlanValue, networkIdentificationTypeValue);
    }

    @Override
    public NAEACIC createNAEACIC(byte[] data) {
        return new NAEACICImpl(data);
    }

    @Override
    public NAEAPreferredCI createNAEAPreferredCI(NAEACIC naeaPreferredCIC, MAPExtensionContainer extensionContainer) {
        return new NAEAPreferredCIImpl(naeaPreferredCIC, extensionContainer);
    }

    @Override
    public Category createCategory(int data) {
        return new CategoryImpl(data);
    }

    @Override
    public Category createCategory(CategoryValue data) {
        return new CategoryImpl(data);
    }

    @Override
    public RoutingInfo createRoutingInfo(ISDNAddressString roamingNumber) {
        return new RoutingInfoImpl(roamingNumber);
    }

    @Override
    public RoutingInfo createRoutingInfo(ForwardingData forwardingData) {
        return new RoutingInfoImpl(forwardingData);
    }

    @Override
    public ExtendedRoutingInfo createExtendedRoutingInfo(RoutingInfo routingInfo) {
        return new ExtendedRoutingInfoImpl(routingInfo);
    }

    @Override
    public ExtendedRoutingInfo createExtendedRoutingInfo(CamelRoutingInfo camelRoutingInfo) {
        return new ExtendedRoutingInfoImpl(camelRoutingInfo);
    }

    @Override
    public TMSI createTMSI(byte[] data) {
        return new TMSIImpl(data);
    }

    @Override
    public CK createCK(byte[] data) {
        return new CKImpl(data);
    }

    @Override
    public Cksn createCksn(int data) {
        return new CksnImpl(data);
    }

    @Override
    public CurrentSecurityContext createCurrentSecurityContext(GSMSecurityContextData gsmSecurityContextData) {
        return new CurrentSecurityContextImpl(gsmSecurityContextData);
    }

    @Override
    public CurrentSecurityContext createCurrentSecurityContext(UMTSSecurityContextData umtsSecurityContextData) {
        return new CurrentSecurityContextImpl(umtsSecurityContextData);
    }

    @Override
    public GSMSecurityContextData createGSMSecurityContextData(Kc kc, Cksn cksn) {
        return new GSMSecurityContextDataImpl(kc, cksn);
    }

    @Override
    public IK createIK(byte[] data) {
        return new IKImpl(data);
    }

    @Override
    public Kc createKc(byte[] data) {
        return new KcImpl(data);
    }

    @Override
    public KSI createKSI(int data) {
        return new KSIImpl(data);
    }

    @Override
    public UMTSSecurityContextData createUMTSSecurityContextData(CK ck, IK ik, KSI ksi) {
        return new UMTSSecurityContextDataImpl(ck, ik, ksi);
    }

    @Override
    public EPSInfo createEPSInfo(PDNGWUpdate pndGwUpdate) {
        return new EPSInfoImpl(pndGwUpdate);
    }

    @Override
    public EPSInfo createEPSInfo(ISRInformation isrInformation) {
        return new EPSInfoImpl(isrInformation);
    }

    @Override
    public ISRInformation createISRInformation(boolean updateMME, boolean cancelSGSN, boolean initialAttachIndicator) {
        return new ISRInformationImpl(updateMME, cancelSGSN, initialAttachIndicator);
    }

    @Override
    public PDNGWUpdate createPDNGWUpdate(APN apn, PDNGWIdentity pdnGwIdentity, Integer contextId,
            MAPExtensionContainer extensionContainer) {
        return new PDNGWUpdateImpl(apn, pdnGwIdentity, contextId, extensionContainer);
    }

    @Override
    public SGSNCapability createSGSNCapability(boolean solsaSupportIndicator, MAPExtensionContainer extensionContainer,
            SuperChargerInfo superChargerSupportedInServingNetworkEntity, boolean gprsEnhancementsSupportIndicator,
            SupportedCamelPhases supportedCamelPhases, SupportedLCSCapabilitySets supportedLCSCapabilitySets,
            OfferedCamel4CSIs offeredCamel4CSIs, boolean smsCallBarringSupportIndicator,
            SupportedRATTypes supportedRATTypesIndicator, SupportedFeatures supportedFeatures, boolean tAdsDataRetrieval,
            Boolean homogeneousSupportOfIMSVoiceOverPSSessions) {
        return new SGSNCapabilityImpl(solsaSupportIndicator, extensionContainer, superChargerSupportedInServingNetworkEntity,
                gprsEnhancementsSupportIndicator, supportedCamelPhases, supportedLCSCapabilitySets, offeredCamel4CSIs,
                smsCallBarringSupportIndicator, supportedRATTypesIndicator, supportedFeatures, tAdsDataRetrieval,
                homogeneousSupportOfIMSVoiceOverPSSessions);
    }

    @Override
    public OfferedCamel4Functionalities createOfferedCamel4Functionalities(boolean initiateCallAttempt, boolean splitLeg, boolean moveLeg,
            boolean disconnectLeg, boolean entityReleased, boolean dfcWithArgument, boolean playTone, boolean dtmfMidCall, boolean chargingIndicator,
            boolean alertingDP, boolean locationAtAlerting, boolean changeOfPositionDP, boolean orInteractions, boolean warningToneEnhancements,
            boolean cfEnhancements, boolean subscribedEnhancedDialledServices, boolean servingNetworkEnhancedDialledServices,
            boolean criteriaForChangeOfPositionDP, boolean serviceChangeDP, boolean collectInformation) {
        return new OfferedCamel4FunctionalitiesImpl(initiateCallAttempt, splitLeg, moveLeg, disconnectLeg, entityReleased, dfcWithArgument, playTone,
                dtmfMidCall, chargingIndicator, alertingDP, locationAtAlerting, changeOfPositionDP, orInteractions, warningToneEnhancements, cfEnhancements,
                subscribedEnhancedDialledServices, servingNetworkEnhancedDialledServices, criteriaForChangeOfPositionDP, serviceChangeDP, collectInformation);
    }

    @Override
    public GPRSSubscriptionDataWithdraw createGPRSSubscriptionDataWithdraw(boolean allGPRSData) {
        return new GPRSSubscriptionDataWithdrawImpl(allGPRSData);
    }

    @Override
    public GPRSSubscriptionDataWithdraw createGPRSSubscriptionDataWithdraw(ArrayList<Integer> contextIdList) {
        return new GPRSSubscriptionDataWithdrawImpl(contextIdList);
    }

    @Override
    public LSAInformationWithdraw createLSAInformationWithdraw(boolean allLSAData) {
        return new LSAInformationWithdrawImpl(allLSAData);
    }

    @Override
    public LSAInformationWithdraw createLSAInformationWithdraw(ArrayList<LSAIdentity> lsaIdentityList) {
        return new LSAInformationWithdrawImpl(lsaIdentityList);
    }

    @Override
    public SpecificCSIWithdraw createSpecificCSIWithdraw(boolean OCsi, boolean SsCsi, boolean TifCsi, boolean DCsi, boolean VtCsi, boolean MoSmsCsi, boolean MCsi,
            boolean GprsCsi, boolean TCsi, boolean MtSmsCsi, boolean MgCsi, boolean OImCsi, boolean DImCsi, boolean VtImCsi) {
        return new SpecificCSIWithdrawImpl(OCsi, SsCsi, TifCsi, DCsi, VtCsi, MoSmsCsi, MCsi, GprsCsi, TCsi, MtSmsCsi, MgCsi, OImCsi, DImCsi, VtImCsi);
    }

    @Override
    public EPSSubscriptionDataWithdraw createEPSSubscriptionDataWithdraw(boolean allEpsData) {
        return new EPSSubscriptionDataWithdrawImpl(allEpsData);
    }

    @Override
    public EPSSubscriptionDataWithdraw createEPSSubscriptionDataWithdraw(ArrayList<Integer> contextIdList) {
        return new EPSSubscriptionDataWithdrawImpl(contextIdList);
    }

    @Override
    public SSInfo createSSInfo(ForwardingInfo forwardingInfo) {
        return new SSInfoImpl(forwardingInfo);
    }

    @Override
    public SSInfo createSSInfo(CallBarringInfo callBarringInfo) {
        return new SSInfoImpl(callBarringInfo);
    }

    @Override
    public SSInfo createSSInfo(SSData ssData) {
        return new SSInfoImpl(ssData);
    }

    @Override
    public CallBarringFeature createCallBarringFeature(BasicServiceCode basicService, SSStatus ssStatus) {
        return new CallBarringFeatureImpl(basicService, ssStatus);
    }

    @Override
    public ForwardingFeature createForwardingFeature(BasicServiceCode basicService, SSStatus ssStatus, ISDNAddressString torwardedToNumber,
            ISDNAddressString forwardedToSubaddress, ForwardingOptions forwardingOptions, Integer noReplyConditionTime, FTNAddressString longForwardedToNumber) {
        return new ForwardingFeatureImpl(basicService, ssStatus, torwardedToNumber, forwardedToSubaddress, forwardingOptions, noReplyConditionTime,
                longForwardedToNumber);
    }

    @Override
    public ForwardingInfo createForwardingInfo(SSCode ssCode, ArrayList<ForwardingFeature> forwardingFeatureList) {
        return new ForwardingInfoImpl(ssCode, forwardingFeatureList);
    }

    @Override
    public SSData createSSData(SSCode ssCode, SSStatus ssStatus, SSSubscriptionOption ssSubscriptionOption, ArrayList<BasicServiceCode> basicServiceGroupList,
            EMLPPPriority defaultPriority, Integer nbrUser) {
        return new SSDataImpl(ssCode, ssStatus, ssSubscriptionOption, basicServiceGroupList, defaultPriority, nbrUser);
    }

    @Override
    public CallBarringInfo createCallBarringInfo(SSCode ssCode, ArrayList<CallBarringFeature> callBarringFeatureList) {
        return new CallBarringInfoImpl(ssCode, callBarringFeatureList);
    }

    @Override
    public SSForBSCode createSSForBSCode(SSCode ssCode, BasicServiceCode basicService, boolean longFtnSupported) {
        return new SSForBSCodeImpl(ssCode, basicService, longFtnSupported);
    }

    @Override
    public CCBSFeature createCCBSFeature(Integer ccbsIndex, ISDNAddressString bSubscriberNumber, ISDNAddressString bSubscriberSubaddress,
            BasicServiceCode basicServiceCode) {
        return new CCBSFeatureImpl(ccbsIndex, bSubscriberNumber, bSubscriberSubaddress, basicServiceCode);
    }

    @Override
    public GenericServiceInfo createGenericServiceInfo(SSStatus ssStatus, CliRestrictionOption cliRestrictionOption, EMLPPPriority maximumEntitledPriority,
            EMLPPPriority defaultPriority, ArrayList<CCBSFeature> ccbsFeatureList, Integer nbrSB, Integer nbrUser, Integer nbrSN) {
        return new GenericServiceInfoImpl(ssStatus, cliRestrictionOption, maximumEntitledPriority, defaultPriority, ccbsFeatureList, nbrSB, nbrUser, nbrSN);
    }

    @Override
    public TraceReference createTraceReference(byte[] data) {
        return new TraceReferenceImpl(data);
    }

    @Override
    public TraceType createTraceType(int data) {
        return new TraceTypeImpl(data);
    }

    @Override
    public TraceType createTraceType(BssRecordType bssRecordType, MscRecordType mscRecordType, TraceTypeInvokingEvent traceTypeInvokingEvent,
            boolean priorityIndication) {
        return new TraceTypeImpl(bssRecordType, mscRecordType, traceTypeInvokingEvent, priorityIndication);
    }

    @Override
    public TraceType createTraceType(HlrRecordType hlrRecordType, TraceTypeInvokingEvent traceTypeInvokingEvent, boolean priorityIndication) {
        return new TraceTypeImpl(hlrRecordType, traceTypeInvokingEvent, priorityIndication);
    }

    @Override
    public TraceDepthList createTraceDepthList(TraceDepth mscSTraceDepth, TraceDepth mgwTraceDepth, TraceDepth sgsnTraceDepth, TraceDepth ggsnTraceDepth,
            TraceDepth rncTraceDepth, TraceDepth bmscTraceDepth, TraceDepth mmeTraceDepth, TraceDepth sgwTraceDepth, TraceDepth pgwTraceDepth,
            TraceDepth enbTraceDepth) {
        return new TraceDepthListImpl(mscSTraceDepth, mgwTraceDepth, sgsnTraceDepth, ggsnTraceDepth, rncTraceDepth, bmscTraceDepth, mmeTraceDepth,
                sgwTraceDepth, pgwTraceDepth, enbTraceDepth);
    }

    @Override
    public TraceNETypeList createTraceNETypeList(boolean mscS, boolean mgw, boolean sgsn, boolean ggsn, boolean rnc, boolean bmSc, boolean mme, boolean sgw,
            boolean pgw, boolean enb) {
        return new TraceNETypeListImpl(mscS, mgw, sgsn, ggsn, rnc, bmSc, mme, sgw, pgw, enb);
    }

    @Override
    public MSCSInterfaceList createMSCSInterfaceList(boolean a, boolean iu, boolean mc, boolean mapG, boolean mapB, boolean mapE, boolean mapF, boolean cap,
            boolean mapD, boolean mapC) {
        return new MSCSInterfaceListImpl(a, iu, mc, mapG, mapB, mapE, mapF, cap, mapD, mapC);
    }

    @Override
    public MGWInterfaceList createMGWInterfaceList(boolean mc, boolean nbUp, boolean iuUp) {
        return new MGWInterfaceListImpl(mc, nbUp, iuUp);
    }

    @Override
    public SGSNInterfaceList createSGSNInterfaceList(boolean gb, boolean iu, boolean gn, boolean mapGr, boolean mapGd, boolean mapGf, boolean gs, boolean ge,
            boolean s3, boolean s4, boolean s6d) {
        return new SGSNInterfaceListImpl(gb, iu, gn, mapGr, mapGd, mapGf, gs, ge, s3, s4, s6d);
    }

    @Override
    public GGSNInterfaceList createGGSNInterfaceList(boolean gn, boolean gi, boolean gmb) {
        return new GGSNInterfaceListImpl(gn, gi, gmb);
    }

    @Override
    public RNCInterfaceList createRNCInterfaceList(boolean iu, boolean iur, boolean iub, boolean uu) {
        return new RNCInterfaceListImpl(iu, iur, iub, uu);
    }

    @Override
    public BMSCInterfaceList createBMSCInterfaceList(boolean gmb) {
        return new BMSCInterfaceListImpl(gmb);
    }

    @Override
    public MMEInterfaceList createMMEInterfaceList(boolean s1Mme, boolean s3, boolean s6a, boolean s10, boolean s11) {
        return new MMEInterfaceListImpl(s1Mme, s3, s6a, s10, s11);
    }

    @Override
    public SGWInterfaceList createSGWInterfaceList(boolean s4, boolean s5, boolean s8b, boolean s11, boolean gxc) {
        return new SGWInterfaceListImpl(s4, s5, s8b, s11, gxc);
    }

    @Override
    public PGWInterfaceList createPGWInterfaceList(boolean s2a, boolean s2b, boolean s2c, boolean s5, boolean s6b, boolean gx, boolean s8b, boolean sgi) {
        return new PGWInterfaceListImpl(s2a, s2b, s2c, s5, s6b, gx, s8b, sgi);
    }

    @Override
    public ENBInterfaceList createENBInterfaceList(boolean s1Mme, boolean x2, boolean uu) {
        return new ENBInterfaceListImpl(s1Mme, x2, uu);
    }

    @Override
    public TraceInterfaceList createTraceInterfaceList(MSCSInterfaceList mscSList, MGWInterfaceList mgwList, SGSNInterfaceList sgsnList,
            GGSNInterfaceList ggsnList, RNCInterfaceList rncList, BMSCInterfaceList bmscList, MMEInterfaceList mmeList, SGWInterfaceList sgwList,
            PGWInterfaceList pgwList, ENBInterfaceList enbList) {
        return new TraceInterfaceListImpl(mscSList, mgwList, sgsnList, ggsnList, rncList, bmscList, mmeList, sgwList, pgwList, enbList);
    }

    @Override
    public MSCSEventList createMSCSEventList(boolean moMtCall, boolean moMtSms, boolean luImsiAttachImsiDetach, boolean handovers, boolean ss) {
        return new MSCSEventListImpl(moMtCall, moMtSms, luImsiAttachImsiDetach, handovers, ss);
    }

    @Override
    public MGWEventList createMGWEventList(boolean context) {
        return new MGWEventListImpl(context);
    }

    @Override
    public SGSNEventList createSGSNEventList(boolean pdpContext, boolean moMtSms, boolean rauGprsAttachGprsDetach, boolean mbmsContext) {
        return new SGSNEventListImpl(pdpContext, moMtSms, rauGprsAttachGprsDetach, mbmsContext);
    }

    @Override
    public GGSNEventList createGGSNEventList(boolean pdpContext, boolean mbmsContext) {
        return new GGSNEventListImpl(pdpContext, mbmsContext);
    }

    @Override
    public BMSCEventList createBMSCEventList(boolean mbmsMulticastServiceActivation) {
        return new BMSCEventListImpl(mbmsMulticastServiceActivation);
    }

    @Override
    public MMEEventList createMMEEventList(boolean ueInitiatedPDNconectivityRequest, boolean serviceRequestts, boolean initialAttachTrackingAreaUpdateDetach,
            boolean ueInitiatedPDNdisconnection, boolean bearerActivationModificationDeletion, boolean handover) {
        return new MMEEventListImpl(ueInitiatedPDNconectivityRequest, serviceRequestts, initialAttachTrackingAreaUpdateDetach, ueInitiatedPDNdisconnection,
                bearerActivationModificationDeletion, handover);
    }

    @Override
    public SGWEventList createSGWEventList(boolean pdnConnectionCreation, boolean pdnConnectionTermination, boolean bearerActivationModificationDeletion) {
        return new SGWEventListImpl(pdnConnectionCreation, pdnConnectionTermination, bearerActivationModificationDeletion);
    }

    @Override
    public PGWEventList createPGWEventList(boolean pdnConnectionCreation, boolean pdnConnectionTermination, boolean bearerActivationModificationDeletion) {
        return new PGWEventListImpl(pdnConnectionCreation, pdnConnectionTermination, bearerActivationModificationDeletion);
    }

    @Override
    public TraceEventList createTraceEventList(MSCSEventList mscSList, MGWEventList mgwList, SGSNEventList sgsnList, GGSNEventList ggsnList,
            BMSCEventList bmscList, MMEEventList mmeList, SGWEventList sgwList, PGWEventList pgwList) {
        return new TraceEventListImpl(mscSList, mgwList, sgsnList, ggsnList, bmscList, mmeList, sgwList, pgwList);
    }

    @Override
    public GlobalCellId createGlobalCellId(byte[] data) {
        return new GlobalCellIdImpl(data);
    }

    @Override
    public GlobalCellId createGlobalCellId(int mcc, int mnc, int lac, int cellId) throws MAPException {
        return new GlobalCellIdImpl(mcc, mnc, lac, cellId);
    }

    @Override
    public AreaScope createAreaScope(ArrayList<GlobalCellId> cgiList, ArrayList<EUtranCgi> eUtranCgiList, ArrayList<RAIdentity> routingAreaIdList,
            ArrayList<LAIFixedLength> locationAreaIdList, ArrayList<TAId> trackingAreaIdList, MAPExtensionContainer extensionContainer) {
        return new AreaScopeImpl(cgiList, eUtranCgiList, routingAreaIdList, locationAreaIdList, trackingAreaIdList, extensionContainer);
    }

    @Override
    public ListOfMeasurements createListOfMeasurements(byte[] data) {
        return new ListOfMeasurementsImpl(data);
    }

    @Override
    public ReportingTrigger createReportingTrigger(int data) {
        return new ReportingTriggerImpl(data);
    }

    @Override
    public MDTConfiguration createMDTConfiguration(JobType jobType, AreaScope areaScope, ListOfMeasurements listOfMeasurements,
            ReportingTrigger reportingTrigger, ReportInterval reportInterval, ReportAmount reportAmount, Integer eventThresholdRSRP,
            Integer eventThresholdRSRQ, LoggingInterval loggingInterval, LoggingDuration loggingDuration, MAPExtensionContainer extensionContainer) {
        return new MDTConfigurationImpl(jobType, areaScope, listOfMeasurements, reportingTrigger, reportInterval, reportAmount, eventThresholdRSRP,
                eventThresholdRSRQ, loggingInterval, loggingDuration, extensionContainer);
    }

    @Override
    public UUData createUUData(UUIndicator uuIndicator, UUI uuI, boolean uusCFInteraction, MAPExtensionContainer extensionContainer) {
        return new UUDataImpl(uuIndicator, uuI, uusCFInteraction, extensionContainer);
    }

    @Override
    public UUI createUUI(byte[] data) {
        return new UUIImpl(data);
    }

    @Override
    public UUIndicator createUUIndicator(int data) {
        return new UUIndicatorImpl(data);
    }

    @Override
    public CUGIndex createCUGIndex(int data) {
        return new CUGIndexImpl(data);
    }

    @Override
    public ExtQoSSubscribed_MaximumSduSize createExtQoSSubscribed_MaximumSduSize_SourceValue(int data) {
        return new ExtQoSSubscribed_MaximumSduSizeImpl(data, true);
    }

    @Override
    public ExtQoSSubscribed_MaximumSduSize createExtQoSSubscribed_MaximumSduSize(int data) {
        return new ExtQoSSubscribed_MaximumSduSizeImpl(data, false);
    }

    @Override
    public ExtQoSSubscribed_BitRate createExtQoSSubscribed_BitRate_SourceValue(int data) {
        return new ExtQoSSubscribed_BitRateImpl(data, true);
    }

    @Override
    public ExtQoSSubscribed_BitRate createExtQoSSubscribed_BitRate(int data) {
        return new ExtQoSSubscribed_BitRateImpl(data, false);
    }

    @Override
    public ExtQoSSubscribed_BitRateExtended createExtQoSSubscribed_BitRateExtended_SourceValue(int data) {
        return new ExtQoSSubscribed_BitRateExtendedImpl(data, true);
    }

    @Override
    public ExtQoSSubscribed_BitRateExtended createExtQoSSubscribed_BitRateExtended(int data) {
        return new ExtQoSSubscribed_BitRateExtendedImpl(data, false);
    }

    @Override
    public ExtQoSSubscribed_BitRateExtended createExtQoSSubscribed_BitRateExtended_UseNotExtended() {
        return new ExtQoSSubscribed_BitRateExtendedImpl(0, true);
    }

    @Override
    public ExtQoSSubscribed_TransferDelay createExtQoSSubscribed_TransferDelay_SourceValue(int data) {
        return new ExtQoSSubscribed_TransferDelayImpl(data, true);
    }

    @Override
    public ExtQoSSubscribed_TransferDelay createExtQoSSubscribed_TransferDelay(int data) {
        return new ExtQoSSubscribed_TransferDelayImpl(data, false);
    }

    @Override
    public Password createPassword(String data) {
        return new PasswordImpl(data);
    }

    @Override
    public IMSIWithLMSI createIMSIWithLMSI(IMSI imsi, LMSI lmsi) {
        return new IMSIWithLMSIImpl(imsi, lmsi);
    }

    public CAMELSubscriptionInfo createCAMELSubscriptionInfo(OCSI oCsi, ArrayList<OBcsmCamelTdpCriteria> oBcsmCamelTdpCriteriaList, DCSI dCsi, TCSI tCsi,
            ArrayList<TBcsmCamelTdpCriteria> tBcsmCamelTdpCriteriaList, TCSI vtCsi, ArrayList<TBcsmCamelTdpCriteria> vtBcsmCamelTdpCriteriaList,
            boolean tifCsi, boolean tifCsiNotificationToCSE, GPRSCSI gprsCsi, SMSCSI smsCsi, SSCSI ssCsi, MCSI mCsi, MAPExtensionContainer extensionContainer,
            SpecificCSIWithdraw specificCSIWithdraw, SMSCSI mtSmsCsi, ArrayList<MTsmsCAMELTDPCriteria> mTsmsCAMELTDPCriteriaList, MGCSI mgCsi, OCSI oImCsi,
            ArrayList<OBcsmCamelTdpCriteria> oImBcsmCamelTdpCriteriaList, DCSI dImCsi, TCSI vtImCsi, ArrayList<TBcsmCamelTdpCriteria> vtImBcsmCamelTdpCriteriaList) {
        return new CAMELSubscriptionInfoImpl(oCsi, oBcsmCamelTdpCriteriaList, dCsi, tCsi, tBcsmCamelTdpCriteriaList, vtCsi, vtBcsmCamelTdpCriteriaList,
                tifCsi, tifCsiNotificationToCSE, gprsCsi, smsCsi, ssCsi, mCsi, extensionContainer, specificCSIWithdraw, mtSmsCsi, mTsmsCAMELTDPCriteriaList,
                mgCsi, oImCsi, oImBcsmCamelTdpCriteriaList, dImCsi, vtImCsi, vtImBcsmCamelTdpCriteriaList);
    }

    @Override
    public CallBarringData createCallBarringData(ArrayList<ExtCallBarringFeature> callBarringFeatureList, Password password, Integer wrongPasswordAttemptsCounter,
            boolean notificationToCSE, MAPExtensionContainer extensionContainer) {
        return new CallBarringDataImpl(callBarringFeatureList, password, wrongPasswordAttemptsCounter, notificationToCSE, extensionContainer);
    }

    @Override
    public CallForwardingData createCallForwardingData(ArrayList<ExtForwFeature> forwardingFeatureList, boolean notificationToCSE,
            MAPExtensionContainer extensionContainer) {
        return new CallForwardingDataImpl(forwardingFeatureList, notificationToCSE, extensionContainer);
    }

    @Override
    public CallHoldData createCallHoldData(ExtSSStatus ssStatus, boolean notificationToCSE) {
        return new CallHoldDataImpl(ssStatus, notificationToCSE);
    }

    @Override
    public CallWaitingData createCallWaitingData(ArrayList<ExtCwFeature> cwFeatureList, boolean notificationToCSE) {
        return new CallWaitingDataImpl(cwFeatureList, notificationToCSE);
    }

    @Override
    public ClipData createClipData(ExtSSStatus ssStatus, OverrideCategory overrideCategory, boolean notificationToCSE) {
        return new ClipDataImpl(ssStatus, overrideCategory, notificationToCSE);
    }

    @Override
    public ClirData createClirData(ExtSSStatus ssStatus, CliRestrictionOption cliRestrictionOption, boolean notificationToCSE) {
        return new ClirDataImpl(ssStatus, cliRestrictionOption, notificationToCSE);
    }

    @Override
    public EctData createEctData(ExtSSStatus ssStatus, boolean notificationToCSE) {
        return new EctDataImpl(ssStatus, notificationToCSE);
    }

    @Override
    public ExtCwFeature createExtCwFeature(ExtBasicServiceCode basicService, ExtSSStatus ssStatus) {
        return new ExtCwFeatureImpl(basicService, ssStatus);
    }

    @Override
    public MSISDNBS createMSISDNBS(ISDNAddressString msisdn, ArrayList<ExtBasicServiceCode> basicServiceList, MAPExtensionContainer extensionContainer) {
        return new MSISDNBSImpl(msisdn, basicServiceList, extensionContainer);
    }

    @Override
    public ODBInfo createODBInfo(ODBData odbData, boolean notificationToCSE, MAPExtensionContainer extensionContainer) {
        return new ODBInfoImpl(odbData, notificationToCSE, extensionContainer);
    }

    @Override
    public RequestedSubscriptionInfo createRequestedSubscriptionInfo(SSForBSCode requestedSSInfo, boolean odb,
            RequestedCAMELSubscriptionInfo requestedCAMELSubscriptionInfo, boolean supportedVlrCamelPhases, boolean supportedSgsnCamelPhases,
            MAPExtensionContainer extensionContainer, AdditionalRequestedCAMELSubscriptionInfo additionalRequestedCamelSubscriptionInfo, boolean msisdnBsList,
            boolean csgSubscriptionDataRequested, boolean cwInfo, boolean clipInfo, boolean clirInfo, boolean holdInfo, boolean ectInfo) {
        return new RequestedSubscriptionInfoImpl(requestedSSInfo, odb, requestedCAMELSubscriptionInfo, supportedVlrCamelPhases, supportedSgsnCamelPhases,
                extensionContainer, additionalRequestedCamelSubscriptionInfo, msisdnBsList, csgSubscriptionDataRequested, cwInfo, clipInfo,
                clirInfo, holdInfo, ectInfo);
    }

    @Override
    public IpSmGwGuidance createIpSmGwGuidance(int minimumDeliveryTimeValue, int recommendedDeliveryTimeValue,
            MAPExtensionContainer extensionContainer) {
        return new IpSmGwGuidanceImpl(minimumDeliveryTimeValue, recommendedDeliveryTimeValue, extensionContainer);
    }

    @Override
    public CorrelationID createCorrelationID(IMSI hlrId, SipUri sipUriA, SipUri sipUriB) {
        return new CorrelationIDImpl(hlrId, sipUriA, sipUriB);
    }

    /* (non-Javadoc)
     * @see org.restcomm.protocols.ss7.map.api.MAPParameterFactory#createSipUri()
     */
    @Override
    public SipUri createSipUri() {
        return new SipUriImpl();
    }
}

