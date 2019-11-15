package org.restcomm.protocols.ss7.map.load;

import com.google.common.util.concurrent.RateLimiter;
import org.apache.log4j.Logger;
import org.mobicents.protocols.api.IpChannelType;
import org.mobicents.protocols.sctp.netty.NettySctpManagementImpl;
import org.restcomm.protocols.ss7.indicator.NatureOfAddress;
import org.restcomm.protocols.ss7.indicator.RoutingIndicator;
import org.restcomm.protocols.ss7.isup.impl.message.parameter.LocationNumberImpl;
import org.restcomm.protocols.ss7.isup.message.parameter.LocationNumber;
import org.restcomm.protocols.ss7.m3ua.As;
import org.restcomm.protocols.ss7.m3ua.Asp;
import org.restcomm.protocols.ss7.m3ua.AspFactory;
import org.restcomm.protocols.ss7.m3ua.ExchangeType;
import org.restcomm.protocols.ss7.m3ua.Functionality;
import org.restcomm.protocols.ss7.m3ua.IPSPType;
import org.restcomm.protocols.ss7.m3ua.impl.M3UAManagementImpl;
import org.restcomm.protocols.ss7.m3ua.parameter.NetworkAppearance;
import org.restcomm.protocols.ss7.m3ua.parameter.RoutingContext;
import org.restcomm.protocols.ss7.m3ua.parameter.TrafficModeType;
import org.restcomm.protocols.ss7.map.MAPParameterFactoryImpl;
import org.restcomm.protocols.ss7.map.MAPStackImpl;
import org.restcomm.protocols.ss7.map.api.MAPApplicationContext;
import org.restcomm.protocols.ss7.map.api.MAPApplicationContextName;
import org.restcomm.protocols.ss7.map.api.MAPApplicationContextVersion;
import org.restcomm.protocols.ss7.map.api.MAPDialog;
import org.restcomm.protocols.ss7.map.api.MAPException;
import org.restcomm.protocols.ss7.map.api.MAPMessage;
import org.restcomm.protocols.ss7.map.api.MAPProvider;
import org.restcomm.protocols.ss7.map.api.datacoding.CBSDataCodingScheme;
import org.restcomm.protocols.ss7.map.api.dialog.MAPAbortProviderReason;
import org.restcomm.protocols.ss7.map.api.dialog.MAPAbortSource;
import org.restcomm.protocols.ss7.map.api.dialog.MAPNoticeProblemDiagnostic;
import org.restcomm.protocols.ss7.map.api.dialog.MAPRefuseReason;
import org.restcomm.protocols.ss7.map.api.dialog.MAPUserAbortChoice;
import org.restcomm.protocols.ss7.map.api.errors.MAPErrorMessage;
import org.restcomm.protocols.ss7.map.api.primitives.AddressNature;
import org.restcomm.protocols.ss7.map.api.primitives.AddressString;
import org.restcomm.protocols.ss7.map.api.primitives.CellGlobalIdOrServiceAreaIdFixedLength;
import org.restcomm.protocols.ss7.map.api.primitives.CellGlobalIdOrServiceAreaIdOrLAI;
import org.restcomm.protocols.ss7.map.api.primitives.DiameterIdentity;
import org.restcomm.protocols.ss7.map.api.primitives.GSNAddress;
import org.restcomm.protocols.ss7.map.api.primitives.IMEI;
import org.restcomm.protocols.ss7.map.api.primitives.IMSI;
import org.restcomm.protocols.ss7.map.api.primitives.ISDNAddressString;
import org.restcomm.protocols.ss7.map.api.primitives.LMSI;
import org.restcomm.protocols.ss7.map.api.primitives.MAPExtensionContainer;
import org.restcomm.protocols.ss7.map.api.primitives.NumberingPlan;
import org.restcomm.protocols.ss7.map.api.primitives.PlmnId;
import org.restcomm.protocols.ss7.map.api.primitives.SubscriberIdentity;
import org.restcomm.protocols.ss7.map.api.primitives.USSDString;
import org.restcomm.protocols.ss7.map.api.service.lsm.AccuracyFulfilmentIndicator;
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
import org.restcomm.protocols.ss7.map.api.service.lsm.LCSEvent;
import org.restcomm.protocols.ss7.map.api.service.lsm.LCSFormatIndicator;
import org.restcomm.protocols.ss7.map.api.service.lsm.LCSLocationInfo;
import org.restcomm.protocols.ss7.map.api.service.lsm.LCSPriority;
import org.restcomm.protocols.ss7.map.api.service.lsm.LCSPrivacyCheck;
import org.restcomm.protocols.ss7.map.api.service.lsm.LCSQoS;
import org.restcomm.protocols.ss7.map.api.service.lsm.LocationEstimateType;
import org.restcomm.protocols.ss7.map.api.service.lsm.LocationType;
import org.restcomm.protocols.ss7.map.api.service.lsm.MAPDialogLsm;
import org.restcomm.protocols.ss7.map.api.service.lsm.MAPServiceLsmListener;
import org.restcomm.protocols.ss7.map.api.service.lsm.OccurrenceInfo;
import org.restcomm.protocols.ss7.map.api.service.lsm.PeriodicLDRInfo;
import org.restcomm.protocols.ss7.map.api.service.lsm.PositioningDataInformation;
import org.restcomm.protocols.ss7.map.api.service.lsm.PrivacyCheckRelatedAction;
import org.restcomm.protocols.ss7.map.api.service.lsm.ProvideSubscriberLocationRequest;
import org.restcomm.protocols.ss7.map.api.service.lsm.ProvideSubscriberLocationResponse;
import org.restcomm.protocols.ss7.map.api.service.lsm.RANTechnology;
import org.restcomm.protocols.ss7.map.api.service.lsm.ReportingPLMN;
import org.restcomm.protocols.ss7.map.api.service.lsm.ReportingPLMNList;
import org.restcomm.protocols.ss7.map.api.service.lsm.ResponseTime;
import org.restcomm.protocols.ss7.map.api.service.lsm.ResponseTimeCategory;
import org.restcomm.protocols.ss7.map.api.service.lsm.SLRArgExtensionContainer;
import org.restcomm.protocols.ss7.map.api.service.lsm.SendRoutingInfoForLCSRequest;
import org.restcomm.protocols.ss7.map.api.service.lsm.SendRoutingInfoForLCSResponse;
import org.restcomm.protocols.ss7.map.api.service.lsm.ServingNodeAddress;
import org.restcomm.protocols.ss7.map.api.service.lsm.SubscriberLocationReportRequest;
import org.restcomm.protocols.ss7.map.api.service.lsm.SubscriberLocationReportResponse;
import org.restcomm.protocols.ss7.map.api.service.lsm.SupportedGADShapes;
import org.restcomm.protocols.ss7.map.api.service.lsm.TerminationCause;
import org.restcomm.protocols.ss7.map.api.service.lsm.UtranGANSSpositioningData;
import org.restcomm.protocols.ss7.map.api.service.lsm.UtranPositioningDataInfo;
import org.restcomm.protocols.ss7.map.api.service.lsm.VelocityEstimate;
import org.restcomm.protocols.ss7.map.api.service.mobility.MAPDialogMobility;
import org.restcomm.protocols.ss7.map.api.service.mobility.MAPServiceMobilityListener;
import org.restcomm.protocols.ss7.map.api.service.mobility.authentication.AuthenticationFailureReportRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.authentication.AuthenticationFailureReportResponse;
import org.restcomm.protocols.ss7.map.api.service.mobility.authentication.SendAuthenticationInfoRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.authentication.SendAuthenticationInfoResponse;
import org.restcomm.protocols.ss7.map.api.service.mobility.faultRecovery.ForwardCheckSSIndicationRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.faultRecovery.ResetRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.faultRecovery.RestoreDataRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.faultRecovery.RestoreDataResponse;
import org.restcomm.protocols.ss7.map.api.service.mobility.imei.CheckImeiRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.imei.CheckImeiResponse;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.ADDInfo;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.CancelLocationRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.CancelLocationResponse;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.EPSInfo;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.PurgeMSRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.PurgeMSResponse;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.SGSNCapability;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.SendIdentificationRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.SendIdentificationResponse;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.SuperChargerInfo;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.SupportedFeatures;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.SupportedLCSCapabilitySets;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.SupportedRATTypes;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.UESRVCCCapability;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.UpdateGprsLocationRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.UpdateGprsLocationResponse;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.UpdateLocationRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.UpdateLocationResponse;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.UsedRATType;
import org.restcomm.protocols.ss7.map.api.service.mobility.oam.ActivateTraceModeRequest_Mobility;
import org.restcomm.protocols.ss7.map.api.service.mobility.oam.ActivateTraceModeResponse_Mobility;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.AnyTimeInterrogationRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.AnyTimeInterrogationResponse;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.AnyTimeSubscriptionInterrogationRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.AnyTimeSubscriptionInterrogationResponse;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.DomainType;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.EUtranCgi;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.GPRSMSClass;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.GeodeticInformation;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.GeographicalInformation;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.LocationInformation;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.LocationInformationEPS;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.LocationInformationGPRS;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.LocationNumberMap;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.MNPInfoRes;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.MSClassmark2;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.MSNetworkCapability;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.MSRadioAccessCapability;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.NotReachableReason;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.NumberPortabilityStatus;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.PDPContextInfo;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.PSSubscriberState;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.PSSubscriberStateChoice;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.ProvideSubscriberInfoRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.ProvideSubscriberInfoResponse;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.RAIdentity;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.RequestedInfo;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.RouteingNumber;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.SubscriberInfo;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.SubscriberState;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.SubscriberStateChoice;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.TAId;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.TypeOfShape;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.UserCSGInformation;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.APN;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.DeleteSubscriberDataRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.DeleteSubscriberDataResponse;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.InsertSubscriberDataRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.InsertSubscriberDataResponse;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.LSAIdentity;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.OfferedCamel4CSIs;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.SupportedCamelPhases;
import org.restcomm.protocols.ss7.map.datacoding.CBSDataCodingSchemeImpl;
import org.restcomm.protocols.ss7.map.primitives.AddressStringImpl;
import org.restcomm.protocols.ss7.map.primitives.CellGlobalIdOrServiceAreaIdFixedLengthImpl;
import org.restcomm.protocols.ss7.map.primitives.CellGlobalIdOrServiceAreaIdOrLAIImpl;
import org.restcomm.protocols.ss7.map.primitives.DiameterIdentityImpl;
import org.restcomm.protocols.ss7.map.primitives.GSNAddressImpl;
import org.restcomm.protocols.ss7.map.primitives.IMEIImpl;
import org.restcomm.protocols.ss7.map.primitives.IMSIImpl;
import org.restcomm.protocols.ss7.map.primitives.ISDNAddressStringImpl;
import org.restcomm.protocols.ss7.map.primitives.LMSIImpl;
import org.restcomm.protocols.ss7.map.primitives.PlmnIdImpl;
import org.restcomm.protocols.ss7.map.primitives.SubscriberIdentityImpl;
import org.restcomm.protocols.ss7.map.primitives.USSDStringImpl;
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
import org.restcomm.protocols.ss7.map.service.lsm.LocationTypeImpl;
import org.restcomm.protocols.ss7.map.service.lsm.PeriodicLDRInfoImpl;
import org.restcomm.protocols.ss7.map.service.lsm.PositioningDataInformationImpl;
import org.restcomm.protocols.ss7.map.service.lsm.ReportingPLMNImpl;
import org.restcomm.protocols.ss7.map.service.lsm.ReportingPLMNListImpl;
import org.restcomm.protocols.ss7.map.service.lsm.ResponseTimeImpl;
import org.restcomm.protocols.ss7.map.service.lsm.ServingNodeAddressImpl;
import org.restcomm.protocols.ss7.map.service.lsm.SupportedGADShapesImpl;
import org.restcomm.protocols.ss7.map.service.lsm.UtranGANSSpositioningDataImpl;
import org.restcomm.protocols.ss7.map.service.lsm.UtranPositioningDataInfoImpl;
import org.restcomm.protocols.ss7.map.service.lsm.VelocityEstimateImpl;
import org.restcomm.protocols.ss7.map.service.mobility.locationManagement.ADDInfoImpl;
import org.restcomm.protocols.ss7.map.service.mobility.locationManagement.SGSNCapabilityImpl;
import org.restcomm.protocols.ss7.map.service.mobility.locationManagement.SupportedLCSCapabilitySetsImpl;
import org.restcomm.protocols.ss7.map.service.mobility.locationManagement.SupportedRATTypesImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.EUtranCgiImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.GeodeticInformationImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.GeographicalInformationImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.LocationInformationEPSImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.LocationNumberMapImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.MSNetworkCapabilityImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.MSRadioAccessCapabilityImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.RAIdentityImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.RequestedInfoImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.RouteingNumberImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberInformation.TAIdImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.APNImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.LSAIdentityImpl;
import org.restcomm.protocols.ss7.map.service.mobility.subscriberManagement.SupportedCamelPhasesImpl;
import org.restcomm.protocols.ss7.sccp.LoadSharingAlgorithm;
import org.restcomm.protocols.ss7.sccp.LongMessageRuleType;
import org.restcomm.protocols.ss7.sccp.NetworkIdState;
import org.restcomm.protocols.ss7.sccp.OriginationType;
import org.restcomm.protocols.ss7.sccp.Router;
import org.restcomm.protocols.ss7.sccp.RuleType;
import org.restcomm.protocols.ss7.sccp.SccpResource;
import org.restcomm.protocols.ss7.sccp.impl.SccpStackImpl;
import org.restcomm.protocols.ss7.sccp.impl.parameter.BCDEvenEncodingScheme;
import org.restcomm.protocols.ss7.sccp.impl.parameter.ParameterFactoryImpl;
import org.restcomm.protocols.ss7.sccp.impl.parameter.SccpAddressImpl;
import org.restcomm.protocols.ss7.sccp.parameter.EncodingScheme;
import org.restcomm.protocols.ss7.sccp.parameter.GlobalTitle;
import org.restcomm.protocols.ss7.sccp.parameter.SccpAddress;
import org.restcomm.protocols.ss7.sccpext.impl.SccpExtModuleImpl;
import org.restcomm.protocols.ss7.sccpext.router.RouterExt;
import org.restcomm.protocols.ss7.ss7ext.Ss7ExtInterface;
import org.restcomm.protocols.ss7.ss7ext.Ss7ExtInterfacePAiC;
import org.restcomm.protocols.ss7.tcap.TCAPStackImpl;
import org.restcomm.protocols.ss7.tcap.api.TCAPStack;
import org.restcomm.protocols.ss7.tcap.asn.ApplicationContextName;
import org.restcomm.protocols.ss7.tcap.asn.comp.Problem;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Random;

import static org.restcomm.protocols.ss7.map.api.service.lsm.LCSEvent.emergencyCallOrigination;
import static org.restcomm.protocols.ss7.map.api.service.lsm.LocationEstimateType.currentLocation;

/**
 * @author <a href="mailto:fernando.mendioroz@gmail.com"> Fernando Mendioroz </a>
 */
public class MobilityLsmClientServer extends MobilityLsmTestHarness implements MAPServiceMobilityListener, MAPServiceLsmListener {

    private static String gt01="-";
    private static String gt02="-";
    private static Logger logger = Logger.getLogger(MobilityLsmClientServer.class);

    // TCAP
    private TCAPStack serverTcapStack;
    private TCAPStack clientTcapStack;

    // MAP
    private MAPStackImpl serverMapStack;
    private MAPProvider serverMapProvider;
    private MAPStackImpl clientMapStack;
    private MAPProvider clientMapProvider;

    // SCCP
    SccpExtModuleImpl sccpExtModule;
    private SccpStackImpl serverSccpStack;
    private SccpResource serverSccpResource;
    private SccpStackImpl clientSccpStack;
    private SccpResource clientSccpResource;
    private Router router;
    private RouterExt routerExt;

    // M3UA
    private M3UAManagementImpl serverM3UAMgmt;
    private M3UAManagementImpl clientM3UAMgmt;

    // SCTP
    private NettySctpManagementImpl serverSctpManagement;
    private NettySctpManagementImpl clientSctpManagement;

    // a ramp-up period is required for performance testing.
    int serverEndCount = 0;
    int clientEndCount = -100;

    // AtomicInteger nbConcurrentDialogs = new AtomicInteger(0);

    // volatile long start = 0L;
    volatile long serverStart = System.currentTimeMillis();
    volatile long clientStart = 0L;
    volatile long prev = 0L;

    private RateLimiter rateLimiterObj = null;

    protected void initializeServerStack(IpChannelType ipChannelType) throws Exception {

        this.initServerSCTP(ipChannelType);

        // Initialize M3UA first
        this.initServerM3UA();

        // Initialize SCCP
        this.initServerSCCP();

        // Initialize TCAP
        this.initServerTCAP();

        // Initialize MAP
        this.initServerMAP();

        // Start ASP
        this.serverM3UAMgmt.startAsp("RASP1");
    }

    protected void initializeClientStack(IpChannelType ipChannelType) throws Exception {

        this.rateLimiterObj = RateLimiter.create(MAXCONCURRENTDIALOGS); // rate

        this.initClientSCTP(ipChannelType);

        // Initialize M3UA first
        this.initClientM3UA();

        // Initialize SCCP
        this.initClientSCCP();

        // Initialize TCAP
        this.initClientTCAP();

        // Initialize MAP
        this.initClientMAP();

        // Start ASP
        this.clientM3UAMgmt.startAsp("ASP1");
    }

    private void initServerSCTP(IpChannelType ipChannelType) throws Exception {
        this.serverSctpManagement = new NettySctpManagementImpl("Server");
        // this.serverSctpManagement.setSingleThread(false);
        this.serverSctpManagement.start();
        this.serverSctpManagement.setConnectDelay(10000);
        this.serverSctpManagement.removeAllResourses();

        // 1. Create SCTP Server
        serverSctpManagement.addServer(SERVER_NAME, SERVER_IP, SERVER_PORT, ipChannelType, null);

        // 2. Create SCTP Server Association
        serverSctpManagement.addServerAssociation(CLIENT_IP, CLIENT_PORT, SERVER_NAME, SERVER_ASSOCIATION_NAME, ipChannelType);

        // 3. Start Server
        serverSctpManagement.startServer(SERVER_NAME);
    }

    private void initClientSCTP(IpChannelType ipChannelType) throws Exception {
        this.clientSctpManagement = new NettySctpManagementImpl("Client");
        // this.clientSctpManagement.setSingleThread(false);
        this.clientSctpManagement.start();
        this.clientSctpManagement.setConnectDelay(10000);
        this.clientSctpManagement.removeAllResourses();

        // 1. Create SCTP Association
        clientSctpManagement.addAssociation(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT, CLIENT_ASSOCIATION_NAME,
            ipChannelType, null);
    }

    private void initServerM3UA() throws Exception {
        this.serverM3UAMgmt = new M3UAManagementImpl("Server", null, new Ss7ExtInterfacePAiC());
        this.serverM3UAMgmt.setTransportManagement(this.serverSctpManagement);
        this.serverM3UAMgmt.setDeliveryMessageThreadCount(DELIVERY_TRANSFER_MESSAGE_THREAD_COUNT);
        this.serverM3UAMgmt.start();
        this.serverM3UAMgmt.removeAllResourses();

        // Step 1 : Create App Server
        RoutingContext rc = factory.createRoutingContext(new long[] { 100L });
        TrafficModeType trafficModeType = factory.createTrafficModeType(TrafficModeType.Loadshare);
        NetworkAppearance na = factory.createNetworkAppearance(102L);
        As as = this.serverM3UAMgmt.createAs("RAS1", Functionality.SGW, ExchangeType.SE, IPSPType.CLIENT, rc, trafficModeType,
            1, null);

        // Step 2 : Create ASP
        AspFactory aspFactor = this.serverM3UAMgmt.createAspFactory("RASP1", SERVER_ASSOCIATION_NAME);

        // Step3 : Assign ASP to AS
        Asp asp = this.serverM3UAMgmt.assignAspToAs("RAS1", "RASP1");

        // Step 4: Add Route. Remote point code is 2
        this.serverM3UAMgmt.addRoute(CLIENT_SPC, -1, -1, "RAS1");
    }

    private void initClientM3UA() throws Exception {
        this.clientM3UAMgmt = new M3UAManagementImpl("Client", null, new Ss7ExtInterfacePAiC());
        this.clientM3UAMgmt.setTransportManagement(this.clientSctpManagement);
        this.clientM3UAMgmt.setDeliveryMessageThreadCount(DELIVERY_TRANSFER_MESSAGE_THREAD_COUNT);
        this.clientM3UAMgmt.start();
        this.clientM3UAMgmt.removeAllResourses();

        // m3ua as create rc <rc> <ras-name>
        RoutingContext rc = factory.createRoutingContext(new long[]{100L});
        TrafficModeType trafficModeType = factory.createTrafficModeType(TrafficModeType.Loadshare);
        NetworkAppearance na = factory.createNetworkAppearance(102L);
        this.clientM3UAMgmt.createAs("AS1", Functionality.AS, ExchangeType.SE, IPSPType.CLIENT, rc, trafficModeType, 1, null);

        // Step 2 : Create ASP
        this.clientM3UAMgmt.createAspFactory("ASP1", CLIENT_ASSOCIATION_NAME);

        // Step3 : Assign ASP to AS
        Asp asp = this.clientM3UAMgmt.assignAspToAs("AS1", "ASP1");

        // Step 4: Add Route. Remote point code is 2
        clientM3UAMgmt.addRoute(SERVER_SPC, -1, -1, "AS1");

    }

    private void initServerSCCP() throws Exception {
        Ss7ExtInterface ss7ExtInterface = new Ss7ExtInterfacePAiC();
        sccpExtModule = new SccpExtModuleImpl();
        ss7ExtInterface.setSs7ExtSccpInterface(sccpExtModule);
        this.serverSccpStack = new SccpStackImpl("MapLoadServerSccpStack", ss7ExtInterface);
        this.serverSccpStack.setMtp3UserPart(1, this.serverM3UAMgmt);

        this.serverSccpStack.start();
        this.serverSccpStack.removeAllResourses();

        this.router = this.serverSccpStack.getRouter();
        this.routerExt = sccpExtModule.getRouterExt();

        this.serverSccpStack.getSccpResource().addRemoteSpc(0, CLIENT_SPC, 0, 0);
        this.serverSccpStack.getSccpResource().addRemoteSsn(0, CLIENT_SPC, CLIENT_SSN, 0, false);

        this.serverSccpStack.getRouter().addMtp3ServiceAccessPoint(1, 1, SERVER_SPC, NETWORK_INDICATOR, 0, null);
        this.serverSccpStack.getRouter().addMtp3Destination(1, 1, CLIENT_SPC, CLIENT_SPC, 0, 255, 255);

        ParameterFactoryImpl fact = new ParameterFactoryImpl();
        EncodingScheme ec = new BCDEvenEncodingScheme();
        GlobalTitle gt1 = fact.createGlobalTitle("-", 0, org.restcomm.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, ec,
            NatureOfAddress.INTERNATIONAL);
        GlobalTitle gt2 = fact.createGlobalTitle("-", 0, org.restcomm.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, ec,
            NatureOfAddress.INTERNATIONAL);
        SccpAddress localAddress = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt1, SERVER_SPC, SERVER_SSN);
        this.routerExt.addRoutingAddress(1, localAddress);
        SccpAddress remoteAddress = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt2, CLIENT_SPC, CLIENT_SSN);
        this.routerExt.addRoutingAddress(2, remoteAddress);

        GlobalTitle gt = fact.createGlobalTitle("*", 0, org.restcomm.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, ec,
            NatureOfAddress.INTERNATIONAL);
        SccpAddress pattern = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt, 0, 0);
        this.routerExt.addRule(1, RuleType.SOLITARY, LoadSharingAlgorithm.Bit0, OriginationType.REMOTE,
            pattern, "K", 1, -1, null, 0, null);
        this.routerExt.addRule(2, RuleType.SOLITARY, LoadSharingAlgorithm.Bit0, OriginationType.LOCAL,
            pattern, "K", 2, -1, null, 0, null);
    }

    private void initClientSCCP() throws Exception {
        Ss7ExtInterface ss7ExtInterface = new Ss7ExtInterfacePAiC();
        sccpExtModule = new SccpExtModuleImpl();
        ss7ExtInterface.setSs7ExtSccpInterface(sccpExtModule);
        this.clientSccpStack = new SccpStackImpl("MapLoadClientSccpStack", ss7ExtInterface);
        this.clientSccpStack.setMtp3UserPart(1, this.clientM3UAMgmt);

        // this.clientSccpStack.setCongControl_Algo(SccpCongestionControlAlgo.levelDepended);

        this.clientSccpStack.start();
        this.clientSccpStack.removeAllResourses();

        this.router = this.clientSccpStack.getRouter();
        this.routerExt = sccpExtModule.getRouterExt();

        this.clientSccpStack.getSccpResource().addRemoteSpc(0, SERVER_SPC, 0, 0);
        this.clientSccpStack.getSccpResource().addRemoteSsn(0, SERVER_SPC, SERVER_SSN, 0, false);

        this.clientSccpStack.getRouter().addMtp3ServiceAccessPoint(1, 1, CLIENT_SPC, NETWORK_INDICATOR, 0, null);
        this.clientSccpStack.getRouter().addMtp3Destination(1, 1, SERVER_SPC, SERVER_SPC, 0, 255, 255);

        ParameterFactoryImpl fact = new ParameterFactoryImpl();
        EncodingScheme ec = new BCDEvenEncodingScheme();
        GlobalTitle gt1 = fact.createGlobalTitle(gt02, 0, org.restcomm.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, ec,
            NatureOfAddress.INTERNATIONAL);
        GlobalTitle gt2 = fact.createGlobalTitle(gt01, 0, org.restcomm.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, ec,
            NatureOfAddress.INTERNATIONAL);
        SccpAddress localAddress = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt1, CLIENT_SPC,
            CLIENT_SSN);
        this.routerExt.addRoutingAddress(1, localAddress);
        SccpAddress remoteAddress = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt2, SERVER_SPC,
            SERVER_SSN);
        this.routerExt.addRoutingAddress(2, remoteAddress);

        SCCP_CLIENT_ADDRESS = localAddress;
        SCCP_SERVER_ADDRESS = remoteAddress;

        GlobalTitle gt = fact.createGlobalTitle("*", 0, org.restcomm.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, ec,
            NatureOfAddress.INTERNATIONAL);
        SccpAddress pattern = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gt, 0, 0);
        this.routerExt.addRule(1, RuleType.SOLITARY, LoadSharingAlgorithm.Bit0, OriginationType.REMOTE, pattern,
            "K", 1, -1, null, 0, null);
        this.routerExt.addRule(2, RuleType.SOLITARY, LoadSharingAlgorithm.Bit0, OriginationType.LOCAL, pattern, "K",
            2, -1, null, 0, null);
        this.clientSccpStack.getRouter().addLongMessageRule(1, 1, 16384, LongMessageRuleType.XUDT_ENABLED);
    }

    private void initServerTCAP() throws Exception {
        this.serverTcapStack = new TCAPStackImpl("TestServer", this.serverSccpStack.getSccpProvider(), SERVER_SSN);
        this.serverTcapStack.start();
        this.serverTcapStack.setDialogIdleTimeout(60000);
        this.serverTcapStack.setInvokeTimeout(30000);
        this.serverTcapStack.setMaxDialogs(MAX_DIALOGS);
    }

    private void initClientTCAP() throws Exception {
        this.clientTcapStack = new TCAPStackImpl("Test", this.clientSccpStack.getSccpProvider(), CLIENT_SSN);
        this.clientTcapStack.start();
        this.clientTcapStack.setDialogIdleTimeout(60000);
        this.clientTcapStack.setInvokeTimeout(30000);
        this.clientTcapStack.setMaxDialogs(MAX_DIALOGS);
    }

    private void initServerMAP() throws Exception {

        this.serverMapStack = new MAPStackImpl("TestServer", this.serverTcapStack.getProvider());
        this.serverMapProvider = this.serverMapStack.getMAPProvider();

        this.serverMapProvider.addMAPDialogListener(this);

        this.serverMapProvider.getMAPServiceMobility().addMAPServiceListener(this);
        this.serverMapProvider.getMAPServiceMobility().acivate();

        this.serverMapProvider.getMAPServiceLsm().addMAPServiceListener(this);
        this.serverMapProvider.getMAPServiceLsm().acivate();

        this.serverMapStack.start();
    }

    private void initClientMAP() throws Exception {

        // this.mapStack = new MAPStackImpl(CLIENT_ASSOCIATION_NAME, this.sccpStack.getSccpProvider(), SSN);
        this.clientMapStack = new MAPStackImpl("TestClient", this.clientTcapStack.getProvider());
        this.clientMapProvider = this.clientMapStack.getMAPProvider();

        this.clientMapProvider.addMAPDialogListener(this);

        this.clientMapProvider.getMAPServiceMobility().addMAPServiceListener(this);
        this.clientMapProvider.getMAPServiceMobility().acivate();

        this.clientMapProvider.getMAPServiceLsm().addMAPServiceListener(this);
        this.clientMapProvider.getMAPServiceLsm().acivate();

        this.clientMapStack.start();
    }

    public static void main(String[] args) {

        int noOfCalls = Integer.parseInt(args[0]);
        int noOfConcurrentCalls = Integer.parseInt(args[1]);

        String exec_type ="";
        String imsi="";
        String sgsn_add="";
        String sgsn_num="";

        IpChannelType ipChannelType;
        if (args.length >= 3 && args[2].toLowerCase().equals("tcp")) {
            ipChannelType = IpChannelType.TCP;
        } else {
            ipChannelType = IpChannelType.SCTP;
        }

        logger.info("IpChannelType=" + ipChannelType);

        if (args.length >= 4) {
            MobilityLsmTestHarness.CLIENT_IP = args[3];
        }

        logger.info("CLIENT_IP=" + MobilityLsmTestHarness.CLIENT_IP);

        if (args.length >= 5) {
            MobilityLsmTestHarness.CLIENT_PORT = Integer.parseInt(args[4]);
        }

        logger.info("CLIENT_PORT=" + MobilityLsmTestHarness.CLIENT_PORT);

        if (args.length >= 6) {
            SERVER_IP = args[5];
        }

        logger.info("SERVER_IP=" + SERVER_IP);

        if (args.length >= 7) {
            SERVER_PORT = Integer.parseInt(args[6]);
        }

        logger.info("SERVER_PORT=" + SERVER_PORT);

        if (args.length >= 8) {
            MobilityLsmTestHarness.CLIENT_SPC = Integer.parseInt(args[7]);
        }

        logger.info("CLIENT_SPC=" + MobilityLsmTestHarness.CLIENT_SPC);

        if (args.length >= 9) {
            MobilityLsmTestHarness.SERVER_SPC = Integer.parseInt(args[8]);
        }

        logger.info("SERVER_SPC=" + MobilityLsmTestHarness.SERVER_SPC);

        if (args.length >= 10) {
            MobilityLsmTestHarness.NETWORK_INDICATOR = Integer.parseInt(args[9]);
        }

        logger.info("NETWORK_INDICATOR=" + MobilityLsmTestHarness.NETWORK_INDICATOR);

        if (args.length >= 11) {
            MobilityLsmTestHarness.SERVICE_INDICATOR = Integer.parseInt(args[10]);
        }

        logger.info("SERVICE_INDICATOR=" + MobilityLsmTestHarness.SERVICE_INDICATOR);

        if (args.length >= 12) {
            MobilityLsmTestHarness.CLIENT_SSN = Integer.parseInt(args[11]);
        }

        logger.info("Client SSN=" + MobilityLsmTestHarness.CLIENT_SSN);

        if (args.length >= 13) {
            MobilityLsmTestHarness.SERVER_SSN = Integer.parseInt(args[12]);
        }

        logger.info("Server SSN=" + MobilityLsmTestHarness.SERVER_SSN);

        if (args.length >= 14) {
            MobilityLsmTestHarness.ROUTING_CONTEXT = Integer.parseInt(args[13]);
        }

        logger.info("ROUTING_CONTEXT=" + MobilityLsmTestHarness.ROUTING_CONTEXT);

        if (args.length >= 15) {
            MobilityLsmTestHarness.DELIVERY_TRANSFER_MESSAGE_THREAD_COUNT = Integer.parseInt(args[14]);
        }

        if (args.length >= 16) {
            //this is implemented for 1NCE testing
            exec_type = args[15];
            imsi = args[16];
            sgsn_add = args[17];
            sgsn_num = args[18];
            gt01 = args[16];
            gt02 = args[19];
        }
        logger.info("DELIVERY_TRANSFER_MESSAGE_THREAD_COUNT=" + MobilityLsmTestHarness.DELIVERY_TRANSFER_MESSAGE_THREAD_COUNT);

        if(exec_type.contains("server")){
            final MobilityLsmClientServer server = new MobilityLsmClientServer();
            try {
                server.initializeServerStack(ipChannelType);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        if(exec_type.contains("client")){
            final MobilityLsmClientServer client = new MobilityLsmClientServer();
                try {
                    client.initializeClientStack(ipChannelType);

                    Thread.sleep(20000);

                    while (client.clientEndCount < NDIALOGS) {
                        /*
                         * while (client.nbConcurrentDialogs.intValue() >= MAXCONCURRENTDIALOGS) {
                         *
                         * logger.warn("Number of concurrent MAP dialog's = " + client.nbConcurrentDialogs.intValue() +
                         * " Waiting for max dialog count to go down!");
                         *
                         * synchronized (client) { try { client.wait(); } catch (Exception ex) { } } }// end of while
                         * (client.nbConcurrentDialogs.intValue() >= MAXCONCURRENTDIALOGS)
                         */

                        if (client.clientEndCount < 0) {
                            client.clientStart = System.currentTimeMillis();
                            client.prev = client.clientStart;
                             // logger.warn("StartTime = " + client.start);
                        }

                        //client.initiateMapAti();
                        //client.initiateMapSRIforLCS();
                        //client.initiateMapPSL();
                        //client.initiateMapSLR();
                        client.initiateUpdateGprsLocation(imsi, sgsn_add, sgsn_num);
                    }

                } catch (Exception e) {
                    e.printStackTrace();
                }
        }
    }

    private void initiateMapAti() throws MAPException {
        try {
            NetworkIdState networkIdState = this.clientMapStack.getMAPProvider().getNetworkIdState(0);
            if (!(networkIdState == null || networkIdState.isAvailavle() && networkIdState.getCongLevel() == 0)) {
                // congestion or unavailable
                logger.warn("Outgoing congestion control: MAP load test client: networkIdState=" + networkIdState);
                try {
                    Thread.sleep(3000);
                } catch (InterruptedException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }

            this.rateLimiterObj.acquire();

            // First create Dialog
            AddressString origRef = this.clientMapProvider.getMAPParameterFactory()
                .createAddressString(AddressNature.international_number, NumberingPlan.ISDN, "12345");
            AddressString destRef = this.clientMapProvider.getMAPParameterFactory()
                .createAddressString(AddressNature.international_number, NumberingPlan.ISDN, "67890");
            MAPDialogMobility mapDialogMobility = this.clientMapProvider.getMAPServiceMobility()
                .createNewDialog(
                    MAPApplicationContext.getInstance(MAPApplicationContextName.anyTimeEnquiryContext,
                        MAPApplicationContextVersion.version3),
                    SCCP_CLIENT_ADDRESS, origRef, SCCP_SERVER_ADDRESS, destRef);

            // Then, create parameters for concerning MAP operation
            ISDNAddressString isdnAdd = new ISDNAddressStringImpl(AddressNature.international_number,
                NumberingPlan.ISDN, "59897654321");
            SubscriberIdentity msisdn = new SubscriberIdentityImpl(isdnAdd);

            RequestedInfo requestedInfo = new RequestedInfoImpl(true, true, null, false, null, false, false, false, true);
            // requestedInfo (MAP ATI): last known location and state (idle or busy), no IMEI/MS Classmark/MNP

            ISDNAddressString gsmSCFAddress = new ISDNAddressStringImpl(AddressNature.international_number,
                NumberingPlan.ISDN, "59800001");

            mapDialogMobility.addAnyTimeInterrogationRequest(msisdn, requestedInfo, gsmSCFAddress, null);

            // This will initiate the TC-BEGIN with INVOKE component
            mapDialogMobility.send();
        } catch (MAPException e) {
            logger.error(String.format("Error while sending MAP ATI:" + e));
        }

    }

    private void initiateMapSRIforLCS() throws MAPException {
        /*
        3GPP TS 29.002 MAP Specification v15.0.0 (2017-03-15)

        13A.1  MAP-SEND-ROUTING-INFO-FOR-LCS Service
         13A.1.1 Definition
            This service is used between the GMLC and the HLR to retrieve the routing information needed for routing a location service request
            to the servicing VMSC, SGSN, MME or 3GPP AAA server. The MAP-SEND-ROUTING-INFO-FOR-LCS is a confirmed service using the primitives
            from table 13A.1/1.

        13A.1.2 Service Primitives

        Table 13A.1/1: MAP-SEND-ROUTING-INFO-FOR-LCS
            Parameter name              Request     Indication  Response    Confirm
            Invoke Id                      M           M(=)        M(=)       M(=)
            MLC Number                     M           M(=)
            MSISDN                         C           C(=)        C          C(=)
            IMSI                           C           C(=)        C          C(=)
            LMSI                                                   C          C(=)
            Network Node Number                                    C          C(=)
            GPRS Node Indicator                                    C          C(=)
            Additional Number                                      C          C(=)
            Supported LCS Capability Sets                          C          C(=)
            Additional LCS Capability Sets                         C          C(=)
            MME Name                                               C          C(=)
            SGSN Name                                              C          C(=)
            AAA Server Name                                        C          C(=)
            V-GMLC Address                                         U          C(=)
            Additional V-GMLC Address                              U          C(=)
            H-GMLC Address                                         C          C(=)
            PPR Address                                            U          C(=)
            User error                                             C          C(=)
            Provider error                                                    O
        */
        try {
            NetworkIdState networkIdState = this.clientMapStack.getMAPProvider().getNetworkIdState(0);
            if (!(networkIdState == null || networkIdState.isAvailavle() && networkIdState.getCongLevel() == 0)) {
                // congestion or unavailable
                logger.warn("Outgoing congestion control: MAP load test client: networkIdState=" + networkIdState);
                try {
                    Thread.sleep(3000);
                } catch (InterruptedException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }

            this.rateLimiterObj.acquire();

            // First create Dialog
            AddressString origRef = this.clientMapProvider.getMAPParameterFactory()
                .createAddressString(AddressNature.international_number, NumberingPlan.ISDN, "12345");
            AddressString destRef = this.clientMapProvider.getMAPParameterFactory()
                .createAddressString(AddressNature.international_number, NumberingPlan.ISDN, "67890");
            MAPDialogLsm mapDialogLsm = clientMapProvider.getMAPServiceLsm()
                .createNewDialog(MAPApplicationContext.getInstance(MAPApplicationContextName.locationSvcGatewayContext,
                    MAPApplicationContextVersion.version3),
                    SCCP_CLIENT_ADDRESS, origRef, SCCP_SERVER_ADDRESS, destRef);

            // Then, create parameters for concerning MAP operation
            ISDNAddressString isdnAdd = new ISDNAddressStringImpl(AddressNature.international_number,
                NumberingPlan.ISDN, "3797554321");
            SubscriberIdentity msisdn = new SubscriberIdentityImpl(isdnAdd);

            ISDNAddressString gmlcAddress = new ISDNAddressStringImpl(AddressNature.international_number,
                NumberingPlan.ISDN, "222333");
/*
            long[] oid = {0, 0, 17, 773, 1, 1, 1};
            String privExtData = "1144";
            byte[] privateExtData = privExtData.getBytes();
            MAPPrivateExtension mapPrivateExtension = new MAPPrivateExtensionImpl(oid, privateExtData);
            ArrayList<MAPPrivateExtension> mapPrivateExtensions = new ArrayList<MAPPrivateExtension>();
            mapPrivateExtensions.add(mapPrivateExtension);
            String pcsExt = "1033";
            byte[] pcsExtensions = pcsExt.getBytes();
            MAPExtensionContainer mapExtensionContainer = new MAPExtensionContainerImpl(mapPrivateExtensions, pcsExtensions);
*/
            MAPExtensionContainer mapExtensionContainer = null;

            mapDialogLsm.addSendRoutingInfoForLCSRequest(gmlcAddress, msisdn, mapExtensionContainer);
            logger.info("SRIforLCS msisdn:" + msisdn + ", sriForLCSIsdnAddress:" + gmlcAddress);

            // This will initiate the TC-BEGIN with INVOKE component
            mapDialogLsm.send();

        } catch (MAPException e) {
            logger.error(String.format("Error while sending MAP SRIforLCS:" + e));
        }

    }

    private void initiateMapPSL() throws MAPException {
        /*
        3GPP TS 29.002 MAP Specification v15.0.0 (2017-03-15)

        13A.2   MAP-PROVIDE-SUBSCRIBER-LOCATION Service

        13A.2.1 Definition
            This service is used by a GMLC to request the location of a target MS from the visited MSC or SGSN at any time.
            This is a confirmed service using the primitives from table 13A.2/1.

        13A.2.2 Service Primitives

        Table 13A.2/1: Provide_Subscriber_Location
            Parameter name                              Request         Indication        Response          Confirm
            Invoke id                                       M               M(=)            M(=)               M(=)
            Location Type                                   M               M(=)
            MLC Number                                      M               M(=)
            LCS Client ID                                   M               M(=)
            Privacy Override                                U               C(=)
            IMSI                                            C               C(=)
            MSISDN                                          C               C(=)
            LMSI                                            C               C(=)
            LCS Priority                                    C               C(=)
            LCS QoS                                         C               C(=)
            IMEI                                            U               C(=)
            Supported GAD Shapes                            C               C(=)
            LCS-Reference Number                            C               C(=)
            LCS Codeword                                    C               C(=)
            LCS Service Type Id                             C               C(=)
            LCS Privacy Check                               C               C(=)
            Area Event Info                                 C               C(=)
            H-GMLC Address                                  C               C(=)
            Reporting PLMN List                             C               C(=)
            PeriodicLDRInfo                                 C               C(=)
            MO-LR Short Circuit Indicator                   C               C(=)            C                   C(=)
            Location Estimate                                                               M                   M(=)
            GERAN Positioning Data                                                          C                   C(=)
            UTRAN Positioning Data                                                          C                   C(=)
            GERAN GANSS Positioning Data                                                    C                   C(=)
            UTRAN GANSS Positioning Data                                                    C                   C(=)
            UTRAN Additional Positioning Data                                               C                   C(=)
            UTRAN Barometric Pressure Measurement                                           C                   C(=)
            UTRAN Civic Address                                                             C                   C(=)
            Age of Location Estimate                                                        C                   C(=)
            Additional Location Estimate                                                    C                   C(=)
            Deferred MT-LR Response Indicator                                               C                   C(=)
            Cell Id Or SAI                                                                  C                   C(=)
            Accuracy Fulfilment Indicator                                                   C                   C(=)
            Target Serving Node for Handover                                                C                   C(=)
            User error                                                                      C                   C(=)
            Provider error                                                                                      O
        */
        try {
            NetworkIdState networkIdState = this.clientMapStack.getMAPProvider().getNetworkIdState(0);
            if (!(networkIdState == null || networkIdState.isAvailavle() && networkIdState.getCongLevel() == 0)) {
                // congestion or unavailable
                logger.warn("Outgoing congestion control: MAP load test client: networkIdState=" + networkIdState);
                try {
                    Thread.sleep(3000);
                } catch (InterruptedException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }

            this.rateLimiterObj.acquire();

            // First create Dialog
            AddressString origRef = this.clientMapProvider.getMAPParameterFactory()
                .createAddressString(AddressNature.international_number, NumberingPlan.ISDN, "12345");
            AddressString destRef = this.clientMapProvider.getMAPParameterFactory()
                .createAddressString(AddressNature.international_number, NumberingPlan.ISDN, "67890");
            MAPDialogLsm mapDialogLsm = clientMapProvider.getMAPServiceLsm()
                .createNewDialog(MAPApplicationContext.getInstance(MAPApplicationContextName.locationSvcEnquiryContext,
                    MAPApplicationContextVersion.version3),
                    SCCP_CLIENT_ADDRESS, origRef, SCCP_SERVER_ADDRESS, destRef);

            // Then, create parameters for concerning MAP operation
            ISDNAddressString msisdn = new ISDNAddressStringImpl(AddressNature.international_number,
                NumberingPlan.ISDN, "3797554321");
            // SubscriberIdentity msisdn = new SubscriberIdentityImpl(isdnAdd);
            ISDNAddressString mlcNumber = new ISDNAddressStringImpl(AddressNature.international_number,
                NumberingPlan.ISDN, "222333");
            LocationEstimateType locationEstimateType = currentLocation;
            // public enum LocationEstimateType {currentLocation(0), currentOrLastKnownLocation(1), initialLocation(2),
            //                                   activateDeferredLocation(3), cancelDeferredLocation(4)..
            DeferredLocationEventType deferredLocationEventType = new DeferredLocationEventTypeImpl();
            deferredLocationEventType.getEnteringIntoArea();
            // DeferredLocationEventType: boolean getMsAvailable(); getEnteringIntoArea(); getLeavingFromArea(); getBeingInsideArea();
            LocationType locationType = new LocationTypeImpl(locationEstimateType, deferredLocationEventType);
            ISDNAddressString externalAddress = new ISDNAddressStringImpl(AddressNature.international_number,
                NumberingPlan.ISDN, "340444567");
            MAPExtensionContainer mapExtensionContainer = null;
            LCSClientExternalID lcsClientExternalID = new LCSClientExternalIDImpl(externalAddress, mapExtensionContainer);
            LCSClientInternalID lcsClientInternalID = LCSClientInternalID.anonymousLocation;
            String clientName = "340012";
            int cbsDataCodingSchemeCode = 15;
            CBSDataCodingScheme cbsDataCodingScheme = new CBSDataCodingSchemeImpl(cbsDataCodingSchemeCode);
            String ussdLcsString = "*911#";
            Charset gsm8Charset = Charset.defaultCharset();
            USSDString ussdString = new USSDStringImpl(ussdLcsString, cbsDataCodingScheme, gsm8Charset);
            LCSFormatIndicator lcsFormatIndicator = LCSFormatIndicator.url;
            LCSClientName lcsClientName = new LCSClientNameImpl(cbsDataCodingScheme, ussdString, lcsFormatIndicator);
            AddressString lcsClientDialedByMS = new AddressStringImpl(AddressNature.international_number, NumberingPlan.ISDN, clientName);
            byte[] apn = new BigInteger("8877665544", 16).toByteArray();
            APN lcsAPN = new APNImpl(apn);
            LCSClientID lcsClientID = new LCSClientIDImpl(LCSClientType.valueAddedServices, lcsClientExternalID, lcsClientInternalID, lcsClientName, lcsClientDialedByMS, lcsAPN, null);
            Boolean privacyOverride = false;
            IMSI imsi = new IMSIImpl("124356871012345");
            String lmsIdStr = "09876543";
            byte[] lmsid = lmsIdStr.getBytes();
            LMSI lmsi = new LMSIImpl(lmsid);
            IMEI imei = new IMEIImpl("01171400466105");
            LCSPriority lcsPriority = LCSPriority.normalPriority;
            boolean ellipsoidPoint = true;
            boolean ellipsoidPointWithUncertaintyCircle = true;
            boolean ellipsoidPointWithUncertaintyEllipse = true;
            boolean polygon = false;
            boolean ellipsoidPointWithAltitude = false;
            boolean ellipsoidPointWithAltitudeAndUncertaintyElipsoid = false;
            boolean ellipsoidArc = false;
            SupportedGADShapes supportedGADShapes = new SupportedGADShapesImpl(ellipsoidPoint, ellipsoidPointWithUncertaintyCircle,
                ellipsoidPointWithUncertaintyEllipse, polygon, ellipsoidPointWithAltitude, ellipsoidPointWithAltitudeAndUncertaintyElipsoid, ellipsoidArc);
            Integer lcsReferenceNumber = 379;
            Integer lcsServiceTypeID = 1;
            // DataCodingScheme codingScheme = new DataCodingSchemeImpl(1);
            USSDString lcsCodewordString = new USSDStringImpl(ussdLcsString, cbsDataCodingScheme, gsm8Charset);
            LCSCodeword lcsCodeword = new LCSCodewordImpl(cbsDataCodingScheme, lcsCodewordString);
            Integer horizontalAccuracy = 100;
            Integer verticalAccuracy = 1000;
            boolean verticalCoordinateRequest = false;
            ResponseTimeCategory responseTimeCategory = ResponseTimeCategory.delaytolerant;
            ResponseTime responseTime = new ResponseTimeImpl(responseTimeCategory);
/*
            long[] oid = {0, 0, 17, 773, 1, 1, 1};
            String pExtData = "1144";
            byte[] privateExtData = pExtData.getBytes();
            MAPPrivateExtension mapPrivateExtension = new MAPPrivateExtensionImpl(oid, privateExtData);
            ArrayList<MAPPrivateExtension> mapPrivateExtensions = new ArrayList<MAPPrivateExtension>();
            mapPrivateExtensions.add(mapPrivateExtension);
            String pcsExts = "1033"
            byte[] pcsExtensions = pcsExts.getBytes();
            MAPExtensionContainer mapExtensionContainer = new MAPExtensionContainerImpl(mapPrivateExtensions, pcsExtensions);
*/
            MAPExtensionContainer extensionContainer = null;
            LCSQoS lcsQoS = new LCSQoSImpl(horizontalAccuracy, verticalAccuracy, verticalCoordinateRequest, responseTime, extensionContainer);
            PrivacyCheckRelatedAction callSessionUnrelated = PrivacyCheckRelatedAction.allowedWithNotification;
            PrivacyCheckRelatedAction callSessionRelated = PrivacyCheckRelatedAction.allowedIfNoResponse;
            LCSPrivacyCheck lcsPrivacyCheck = new LCSPrivacyCheckImpl(callSessionUnrelated, callSessionRelated);
            ArrayList<Area> areaList = new ArrayList<Area>();
            AreaType areaType = AreaType.locationAreaId;
            String aId = "102132";
            byte[] areaId = aId.getBytes();
            AreaIdentification areaIdentification = new AreaIdentificationImpl(areaId);
            Area area1 = new AreaImpl(areaType, areaIdentification);
            areaList.add(area1);
            AreaDefinition areaDefinition = new AreaDefinitionImpl(areaList);
            OccurrenceInfo occurrenceInfo = OccurrenceInfo.oneTimeEvent;
            Integer intervalTime = 10;
            AreaEventInfo areaEventInfo = new AreaEventInfoImpl(areaDefinition, occurrenceInfo, intervalTime);
            byte[] homeGmlcAddress = new BigInteger("999988887777", 16).toByteArray();
            GSNAddress hGmlcAddress = new GSNAddressImpl(homeGmlcAddress);
            boolean moLrShortCircuitIndicator = false;
            int reportingAmount = 3;
            int reportingInterval = 60;
            PeriodicLDRInfo periodicLDRInfo = new PeriodicLDRInfoImpl(reportingAmount, reportingInterval);
            boolean plmnListPrioritized = false;
            ArrayList<ReportingPLMN> plmnList = new ArrayList<ReportingPLMN>();
            String plmnIdStr = "885577";
            byte[] plmnID = plmnIdStr.getBytes();
            PlmnId plmnId = new PlmnIdImpl(plmnID);
            RANTechnology ranTechnology = RANTechnology.umts;
            boolean ranPeriodicLocationSupport = true;
            ReportingPLMN reportingPLMN = new ReportingPLMNImpl(plmnId, ranTechnology, ranPeriodicLocationSupport);
            plmnList.add(reportingPLMN);
            ReportingPLMNList reportingPLMNList = new ReportingPLMNListImpl(plmnListPrioritized, plmnList);

            mapDialogLsm.addProvideSubscriberLocationRequest(locationType, mlcNumber, lcsClientID, privacyOverride, imsi, msisdn, lmsi, imei, lcsPriority,
                lcsQoS, extensionContainer, supportedGADShapes, lcsReferenceNumber, lcsServiceTypeID, lcsCodeword,
                lcsPrivacyCheck, areaEventInfo, hGmlcAddress, moLrShortCircuitIndicator, periodicLDRInfo, reportingPLMNList);
            logger.info("MAP PSL: msisdn:" + msisdn + ", MLC Number:" + mlcNumber);

            // This will initiate the TC-BEGIN with INVOKE component
            mapDialogLsm.send();

        } catch (MAPException e) {
            logger.error(String.format("Error while sending MAP PSL:" + e));
        }

    }

    private void initiateMapSLR() throws MAPException {
        /*
        3GPP TS 29.002 MAP Specification v15.0.0 (2017-03-15)

        13A.3   MAP-SUBSCRIBER-LOCATION-REPORT Service

        13A.3.1 Definition
            This service is used by a VMSC or SGSN to provide the location of a target MS to a GMLC
            when a request for location is either implicitly administered or made at some   earlier time.
            This is a confirmed service using the primitives from table 13A.3/1.

        Table 13A.3/1: Subscriber_Location_Report
            Parameter name                                      Request         Indication       Response     Confirm
            Invoke id                                               M               M(=)            M(=)        M(=)
            LCS Event                                               M               M(=)
            LCS Client ID                                           M               M(=)
            Network Node Number                                     M               M(=)
            IMSI                                                    C               C(=)
            MSISDN                                                  C               C(=)
            NA-ESRD                                                 C               C(=)            C           C(=)
            NA-ESRK                                                 C               C(=)            C           C(=)
            IMEI                                                    U               C(=)
            Location Estimate                                       C               C(=)
            GERAN Positioning Data                                  C               C(=)
            UTRAN Positioning Data                                  C               C(=)
            GERAN GANSS Positioning Data                            C               C(=)
            UTRAN GANSS Positioning Data                            C               C(=)
            UTRAN Additional Positioning Data                       C               C(=)
            UTRAN Barometric Pressure Measurement                   C               C(=)
            UTRAN Civic Address                                     C               C(=)
            Age of Location Estimate                                C               C(=)
            LMSI                                                    U               C(=)
            GPRS Node Indicator                                     C               C(=)
            Additional Location Estimate                            C               C(=)
            Deferred MT-LR Data                                     C               C(=)
            LCS-Reference Number                                    C               C(=)            C           C(=)
            NA-ESRK Request                                         C               C(=)
            Cell Id Or SAI                                          C               C(=)
            H-GMLC Address                                          C               C(=)            C           C(=)
            LCS Service Type Id                                     C               C(=)
            Pseudonym Indicator                                     C               C(=)
            Accuracy Fulfilment Indicator                           C               C(=)
            Sequence Number                                         C               C(=)
            Periodic LDR Info                                       C               C(=)
            MO-LR Short Circuit Indicator                           C               C(=)            C           C(=)
            Target Serving Node for Handover                        C               C(=)
            Reporting PLMN List                                                                     C           C(=)
            User error                                                                              C           C(=)
            Provider error                                                                                      O
            */
        try {
            NetworkIdState networkIdState = this.clientMapStack.getMAPProvider().getNetworkIdState(0);
            if (!(networkIdState == null || networkIdState.isAvailavle() && networkIdState.getCongLevel() == 0)) {
                // congestion or unavailable
                logger.warn("Outgoing congestion control: MAP load test client: networkIdState=" + networkIdState);
                try {
                    Thread.sleep(3000);
                } catch (InterruptedException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }

            this.rateLimiterObj.acquire();

            // First create Dialog
            AddressString origRef = this.clientMapProvider.getMAPParameterFactory()
                .createAddressString(AddressNature.international_number, NumberingPlan.ISDN, "12345");
            AddressString destRef = this.clientMapProvider.getMAPParameterFactory()
                .createAddressString(AddressNature.international_number, NumberingPlan.ISDN, "67890");
            MAPDialogLsm mapDialogLsm = clientMapProvider.getMAPServiceLsm()
                .createNewDialog(MAPApplicationContext.getInstance(MAPApplicationContextName.locationSvcGatewayContext,
                    MAPApplicationContextVersion.version3),
                    SCCP_CLIENT_ADDRESS, origRef, SCCP_SERVER_ADDRESS, destRef);

            // Then, create parameters for concerning MAP operation
            ISDNAddressString msisdn = new ISDNAddressStringImpl(AddressNature.international_number,
                NumberingPlan.ISDN, "3797554321");
            // SubscriberIdentity msisdn = new SubscriberIdentityImpl(isdnAdd);
            ISDNAddressString mscNumber = new ISDNAddressStringImpl(AddressNature.international_number,
                NumberingPlan.ISDN, "598990192837");
            ISDNAddressString sgsnNumber = new ISDNAddressStringImpl(AddressNature.international_number,
                NumberingPlan.ISDN, "598990192837");
            ISDNAddressString naEsrd = new ISDNAddressStringImpl(AddressNature.international_number,
                NumberingPlan.ISDN, "1110101");
            ISDNAddressString naEsrk = new ISDNAddressStringImpl(AddressNature.international_number,
                NumberingPlan.ISDN, "9889277");
            LCSEvent lcsEvent = emergencyCallOrigination;
            // LCS-Event ::= ENUMERATED { emergencyCallOrigination (0), emergencyCallRelease (1), mo-lr (2), ..., deferredmt-lrResponse (3) }
            // -- exception handling: --
            // a SubscriberLocationReport-Arg containing an unrecognized LCS-Event -- shall be rejected by a receiver with a return error cause of unexpected data value
            LocationEstimateType locationEstimateType = currentLocation;
            // public enum LocationEstimateType {currentLocation(0), currentOrLastKnownLocation(1), initialLocation(2), activateDeferredLocation(3),
            //                                   cancelDeferredLocation(4)..
            ISDNAddressString externalAddress = new ISDNAddressStringImpl(AddressNature.international_number,
                NumberingPlan.ISDN, "444567");
/*
            long[] oid = {0, 0, 17, 773, 1, 1, 1};
            String pExtData = "1144";
            byte[] privateExtData = pExtData.getBytes();
            MAPPrivateExtension mapPrivateExtension = new MAPPrivateExtensionImpl(oid, privateExtData);
            ArrayList<MAPPrivateExtension> mapPrivateExtensions = new ArrayList<MAPPrivateExtension>();
            mapPrivateExtensions.add(mapPrivateExtension);
            String pcsExts = "1033"
            byte[] pcsExtensions = pcsExts.getBytes();
            MAPExtensionContainer mapExtensionContainer = new MAPExtensionContainerImpl(mapPrivateExtensions, pcsExtensions);
*/
            MAPExtensionContainer mapExtensionContainer = null;
            LCSClientExternalID lcsClientExternalID = new LCSClientExternalIDImpl(externalAddress, mapExtensionContainer);
            LCSClientInternalID lcsClientInternalID = LCSClientInternalID.broadcastService;
            String clientName = "219023";
            int cbsDataCodingSchemeCode = 15;
            CBSDataCodingScheme cbsDataCodingScheme = new CBSDataCodingSchemeImpl(cbsDataCodingSchemeCode);
            String ussdLcsString = "911";
            Charset gsm8Charset = Charset.defaultCharset();
            USSDString ussdString = new USSDStringImpl(ussdLcsString, cbsDataCodingScheme, gsm8Charset);
            LCSFormatIndicator lcsFormatIndicator = LCSFormatIndicator.url;
            LCSClientName lcsClientName = new LCSClientNameImpl(cbsDataCodingScheme, ussdString, lcsFormatIndicator);
            AddressString lcsClientDialedByMS = new AddressStringImpl(AddressNature.international_number, NumberingPlan.ISDN, clientName);
            byte[] apn = new BigInteger("6763a20b0890", 16).toByteArray();
            APN lcsAPN = new APNImpl(apn);
            LCSClientID lcsClientID = new LCSClientIDImpl(LCSClientType.valueAddedServices, lcsClientExternalID, lcsClientInternalID, lcsClientName, lcsClientDialedByMS, lcsAPN, null);
            ISDNAddressString networkNodeNumber = new ISDNAddressStringImpl(AddressNature.international_number,
                NumberingPlan.ISDN, "5983392892");
            String lmsIdStr = "0a010203";
            byte[] lmsid = lmsIdStr.getBytes();
            LMSI lmsi = new LMSIImpl(lmsid);
            boolean gprsNodeIndicator = true;
            AdditionalNumber additionalNumber = new AdditionalNumberImpl(null, sgsnNumber);
            boolean lcsCapabilitySetRelease98_99 = true;
            boolean lcsCapabilitySetRelease4 = true;
            boolean lcsCapabilitySetRelease5 = true;
            boolean lcsCapabilitySetRelease6 = true;
            boolean lcsCapabilitySetRelease7 = false;
            SupportedLCSCapabilitySets supportedLCSCapabilitySets = new SupportedLCSCapabilitySetsImpl(lcsCapabilitySetRelease98_99, lcsCapabilitySetRelease4,
                lcsCapabilitySetRelease5, lcsCapabilitySetRelease6, lcsCapabilitySetRelease7);
            lcsCapabilitySetRelease7 = true;
            SupportedLCSCapabilitySets additionalLCSCapabilitySets = new SupportedLCSCapabilitySetsImpl(lcsCapabilitySetRelease98_99, lcsCapabilitySetRelease4,
                lcsCapabilitySetRelease5, lcsCapabilitySetRelease6, lcsCapabilitySetRelease7);
            byte[] mme = new BigInteger("8720c00a30a1743401000a", 16).toByteArray();
            DiameterIdentity mmeName = new DiameterIdentityImpl(mme);
            byte[] aaa = new BigInteger("8720c00a30a1743401101112", 16).toByteArray();
            DiameterIdentity aaaServerName = new DiameterIdentityImpl(aaa);
            LCSLocationInfo lcsLocationInfo = new LCSLocationInfoImpl(networkNodeNumber, lmsi, mapExtensionContainer, gprsNodeIndicator, additionalNumber,
                supportedLCSCapabilitySets, additionalLCSCapabilitySets, mmeName, aaaServerName);
            IMSI imsi = new IMSIImpl("748031234567890");
            IMEI imei = new IMEIImpl("011714004661057");
            Integer ageOfLocationEstimate = 0;
            TypeOfShape typeOfShape = TypeOfShape.EllipsoidArc;
            Double latitude = 34.789123;
            Double longitude = -124.902033;
            Double uncertainty = 100.0;
            Double uncertaintySemiMajorAxis = 40.0;
            Double uncertaintySemiMinorAxis = 20.0;
            Double angleOfMajorAxis = 30.0;
            int confidence = 0;
            int altitude = 1500;
            Double uncertaintyAltitude = 500.0;
            int innerRadius = 5;
            Double uncertaintyRadius = 1.50;
            Double offsetAngle = 20.0;
            Double includedAngle = 20.0;
            ExtGeographicalInformation extGeographicalInformation = new ExtGeographicalInformationImpl(typeOfShape, latitude, longitude, uncertainty, uncertaintySemiMajorAxis,
                uncertaintySemiMinorAxis, angleOfMajorAxis, confidence, altitude, uncertaintyAltitude, innerRadius, uncertaintyRadius, offsetAngle, includedAngle);
            SLRArgExtensionContainer slrArgExtensionContainer = null;
            byte[] addLocationEstimate = new BigInteger("9000000002", 16).toByteArray();
            AddGeographicalInformation addGeographicalInformation = new AddGeographicalInformationImpl(addLocationEstimate);
            boolean msAvailable = false;
            boolean enteringIntoArea = true;
            boolean leavingFromArea = true;
            boolean beingInsideArea = true;
            boolean periodicLDR = false;
            DeferredLocationEventType deferredLocationEventType = new DeferredLocationEventTypeImpl(msAvailable, enteringIntoArea, leavingFromArea, beingInsideArea, periodicLDR);
            TerminationCause terminationCause = TerminationCause.congestion;
            DeferredmtlrData deferredmtlrData = new DeferredmtlrDataImpl(deferredLocationEventType, terminationCause, lcsLocationInfo);
            byte[] data = new BigInteger("123456789012", 16).toByteArray();
            PositioningDataInformation positioningDataInformation = new PositioningDataInformationImpl(data);
            byte[] utranData = new BigInteger("43210987654321", 16).toByteArray();
            UtranPositioningDataInfo utranPositioningDataInfo = new UtranPositioningDataInfoImpl(utranData);
            Integer lcsServiceTypeID = 1;
            boolean saiPresent = true;
            Boolean pseudonymIndicator = false;
            AccuracyFulfilmentIndicator accuracyFulfilmentIndicator = AccuracyFulfilmentIndicator.requestedAccuracyNotFulfilled;
            byte[] velEstimate = new BigInteger("0000000001", 16).toByteArray();
            VelocityEstimate velocityEstimate = new VelocityEstimateImpl(velEstimate);
            int reportingAmount = 3;
            int reportingInterval = 600;
            PeriodicLDRInfo periodicLDRInfo = new PeriodicLDRInfoImpl(reportingAmount, reportingInterval);
            boolean b2 = false;
            byte[] cidOrSaiFixedLength = new BigInteger("349a0120b04321", 16).toByteArray();
            CellGlobalIdOrServiceAreaIdFixedLength cellGlobalIdOrServiceAreaIdFixedLength = new CellGlobalIdOrServiceAreaIdFixedLengthImpl(cidOrSaiFixedLength);
            CellGlobalIdOrServiceAreaIdOrLAI cellIdOrSai = new CellGlobalIdOrServiceAreaIdOrLAIImpl(cellGlobalIdOrServiceAreaIdFixedLength);
            byte[] gGanss = new BigInteger("666601019999", 16).toByteArray();
            GeranGANSSpositioningData geranGanssPositioningData = new GeranGANSSpositioningDataImpl(gGanss);
            byte[] uGanss = new BigInteger("777701019898", 16).toByteArray();
            UtranGANSSpositioningData utranGanssPositioningData = new UtranGANSSpositioningDataImpl(uGanss);
            boolean isMsc = true;
            ServingNodeAddress servingNodeAddress = new ServingNodeAddressImpl(networkNodeNumber, isMsc);
            Integer lcsReferenceNumber = 379;
            Integer integer3 = 0;
            byte[] homeGmlcAddress = new BigInteger("3734383439323337", 16).toByteArray();
            GSNAddress hGmlcAddress = new GSNAddressImpl(homeGmlcAddress);

            mapDialogLsm.addSubscriberLocationReportRequest(lcsEvent, lcsClientID, lcsLocationInfo, msisdn, imsi, imei, naEsrd, naEsrk, extGeographicalInformation,
                ageOfLocationEstimate, slrArgExtensionContainer, addGeographicalInformation, deferredmtlrData,
                lcsReferenceNumber, positioningDataInformation, utranPositioningDataInfo, cellIdOrSai, hGmlcAddress,
                lcsServiceTypeID, saiPresent, pseudonymIndicator, accuracyFulfilmentIndicator, velocityEstimate,
                integer3, periodicLDRInfo, b2, geranGanssPositioningData, utranGanssPositioningData, servingNodeAddress);

            logger.info("MAP SLR: msisdn:" + msisdn + ", LCSEvent:" + lcsEvent);
            // This will initiate the TC-BEGIN with INVOKE component
            mapDialogLsm.send();

        } catch (MAPException e) {
            logger.error(String.format("Error while sending MAP SLR:" + e));
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private void initiateUpdateGprsLocation(String IMSI, String sgsn_address, String sgsn_number) throws MAPException {

        /*
        3GPP TS 29.002 MAP Specification v15.4.0 (2018-02)

        8.1.7 MAP_UPDATE_GPRS_LOCATION service
         8.1.7.1 Definition
         This service is used by the SGSN to update the location information stored in the HLR.
         In an EPS, this service is used between IWF and IWF and between IWF and HSS.
         The MAP_UPDATE_GPRS_LOCATION service is a confirmed service using the service primitives given in table 8.1/7.
         8.1.7.2 Service primitives
         Table 8.1/7: MAP_UPDATE_GPRS_LOCATION
            Parameter name                                      Request         Indication       Response     Confirm
            Invoke Id                                               M               M(=)            M(=)         M(=)
            IMSI                                                    M               M(=)
            SGSN number                                             M               M(=)
            SGSN address                                            M               M(=)
            Supported CAMEL Phases                                  C               C(=)
            SoLSA Support Indicator                                 C               C(=)
            Super-Charger Supported in Serving Network Entity       C               C(=)
            GPRS enhancements support indicator                     C               C(=)
            Supported LCS Capability Sets                           C               C(=)
            Offered CAMEL 4 CSIs                                    C               C(=)
            Inform Previous Network Entity                          C               C(=)
            PS LCS Not Supported by UE                              C               C(=)
            V-GMLC Address                                          U               C(=)
            Call barring support indicator                          C               C(=)
            IMEISV                                                  C               C(=)
            Skip Subscriber Data Update                             U               C(=)
            Supported RAT Types Indicator                           U               C(=)
            EPS Info                                                C               C(=)
            Serving Node Type Indicator                             C               C(=)
            Supported Features                                      U               C(=)
            Used RAT Type                                           U               C(=)
            GPRS Subscription Data not needed Indicator             C               C(=)
            EPS Subscription Data Not Needed Indicator              C               C(=)
            Node-Type-Indicator                                     U               C(=)
            Area Restricted Indicator                               C               C(=)
            UE Reachable Indicator                                  C               C(=)
            T-ADS Data Retrieval Support Indicator                  C               C(=)
            Homogeneous Support Of IMS Voice Over PS Sessions       C               C(=)
            Update of Homogeneous Support Of IMS Voice Over PS Sessions C           C(=)
            UE SRVCC Capability                                     C               C(=)
            Equivalent PLMN List                                    C               C(=)
            MME Number for MT SMS                                   C               C(=)
            SMS-Only                                                C               C(=)
            SMS Register Request                                    C               C(=)
            Removal of MME Registration for SMS                     C               C(=)
            MSISDN-less Operation Supported                         C               C(=)
            SGSN Name                                               C               C(=)
            SGSN Realm                                              C               C(=)
            Lgd Support Indicator                                   C               C(=)
            Adjacent-PLMNs                                          C               C(=)
            Reset-IDs Supported                                     C               C(=)
            ADD Capability                                                                          U            C(=)
            SGSN-MME Separation Support Indicator                                                   C            C(=)
            HLR number                                                                              C            C(=)
            MME Registered for SMS                                                                  C            C(=)
            User error                                                                              C            C(=)
            Provider error                                                                                       O
           */

        try {
            NetworkIdState networkIdState = this.clientMapStack.getMAPProvider().getNetworkIdState(0);
            if (!(networkIdState == null || networkIdState.isAvailavle() && networkIdState.getCongLevel() == 0)) {
                // congestion or unavailable
                logger.warn("Outgoing congestion control: MAP load test client: networkIdState=" + networkIdState);
                try {
                    Thread.sleep(3000);
                } catch (InterruptedException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }

            this.rateLimiterObj.acquire();

            // First create Dialog
            AddressString origRef = this.clientMapProvider.getMAPParameterFactory()
                .createAddressString(AddressNature.international_number, NumberingPlan.ISDN, "12345");
            AddressString destRef = this.clientMapProvider.getMAPParameterFactory()
                .createAddressString(AddressNature.international_number, NumberingPlan.ISDN, "67890");
            MAPDialogMobility mapDialogMobility = this.clientMapProvider.getMAPServiceMobility()
                .createNewDialog(
                    MAPApplicationContext.getInstance(MAPApplicationContextName.gprsLocationUpdateContext,
                        MAPApplicationContextVersion.version3),
                    SCCP_CLIENT_ADDRESS, origRef, SCCP_SERVER_ADDRESS, destRef);

            // Then, create parameters for concerning MAP operation
            ISDNAddressString sgsnNumber = new ISDNAddressStringImpl(AddressNature.international_number,
                NumberingPlan.ISDN, sgsn_number);
            ISDNAddressString gsmSCFAddress = new ISDNAddressStringImpl(AddressNature.international_number,
                NumberingPlan.ISDN, sgsn_address);

            IMSI imsi = new IMSIImpl(IMSI);
            byte[] sgsnAddressByteArray = new BigInteger("112233445500", 16).toByteArray();
            GSNAddress sgsnAddress = new GSNAddressImpl(sgsnAddressByteArray);
            MAPExtensionContainer extensionContainer = null;
            boolean solsaSupportIndicator = false;
            SuperChargerInfo superChargerSupportedInServingNetworkEntity = null;
            boolean gprsEnhancementsSupportIndicator = false;
            SupportedCamelPhases supportedCamelPhases = new SupportedCamelPhasesImpl(true, true, true, false);
            OfferedCamel4CSIs offeredCamel4CSIs = null;
            boolean smsCallBarringSupportIndicator = true;
            SupportedRATTypes supportedRATTypesIndicator = new SupportedRATTypesImpl(true, true, false, false, true);
            boolean lcsCapabilitySetRelease98_99 = true;
            boolean lcsCapabilitySetRelease4 = true;
            boolean lcsCapabilitySetRelease5 = true;
            boolean lcsCapabilitySetRelease6 = true;
            boolean lcsCapabilitySetRelease7 = false;
            SupportedLCSCapabilitySets supportedLCSCapabilitySets = new SupportedLCSCapabilitySetsImpl(lcsCapabilitySetRelease98_99, lcsCapabilitySetRelease4,
                lcsCapabilitySetRelease5, lcsCapabilitySetRelease6, lcsCapabilitySetRelease7);
            SupportedFeatures supportedFeatures = null;
            boolean tAdsDataRetrieval = true;
            Boolean homogeneousSupportOfIMSVoiceOverPSSessions = null;
            SGSNCapability sgsnCapability = new SGSNCapabilityImpl(solsaSupportIndicator, extensionContainer, superChargerSupportedInServingNetworkEntity,
                gprsEnhancementsSupportIndicator, supportedCamelPhases, supportedLCSCapabilitySets, offeredCamel4CSIs, smsCallBarringSupportIndicator,
                supportedRATTypesIndicator, supportedFeatures, tAdsDataRetrieval, homogeneousSupportOfIMSVoiceOverPSSessions);
            boolean informPreviousNetworkEntity = false;
            boolean psLCSNotSupportedByUE = false;
            byte[] visitedGmlcAddress = new BigInteger("112233445500", 16).toByteArray();
            GSNAddress vGmlcAddress = new GSNAddressImpl(visitedGmlcAddress);
            IMEI imeisv = new IMEIImpl("01171400466105");
            boolean skipSubscriberDataUpdate = true;
            ADDInfo addInfo = new ADDInfoImpl(imeisv, skipSubscriberDataUpdate);
            EPSInfo epsInfo = null;
            boolean servingNodeTypeIndicator = false;
            UsedRATType usedRATType = UsedRATType.utran;
            boolean gprsSubscriptionDataNotNeeded = false;
            boolean nodeTypeIndicator = false;
            boolean areaRestricted = true;
            boolean ueReachableIndicator = false;
            boolean epsSubscriptionDataNotNeeded = true;
            UESRVCCCapability uesrvccCapability = UESRVCCCapability.ueSrvccSupported;

            mapDialogMobility.addUpdateGprsLocationRequest(imsi, sgsnNumber, sgsnAddress, extensionContainer, sgsnCapability, informPreviousNetworkEntity,
                psLCSNotSupportedByUE, vGmlcAddress, addInfo, epsInfo, servingNodeTypeIndicator, skipSubscriberDataUpdate, usedRATType, gprsSubscriptionDataNotNeeded,
                nodeTypeIndicator, areaRestricted, ueReachableIndicator, epsSubscriptionDataNotNeeded, uesrvccCapability);

            // This will initiate the TC-BEGIN with INVOKE component
            mapDialogMobility.send();
        } catch (MAPException e) {
            logger.error(String.format("Error while sending MAP ATI:" + e));
        }
    }


    public void onAnyTimeInterrogationRequest(AnyTimeInterrogationRequest ind) {

        if (logger.isDebugEnabled()) {
            logger.debug(
                String.format("onAnyTimeInterrogationRequest for DialogId=%d", ind.getMAPDialog().getLocalDialogId()));
        }
        if (logger.isInfoEnabled()) {
            logger.info(String.format("onAnyTimeInterrogationRequest for DialogId=%d", ind.getMAPDialog().getLocalDialogId()));
        }

        // Generate MAP errors for specific MSISDNs
        String msisdnAddress = ind.getSubscriberIdentity().getMSISDN().getAddress();

        Random rand = new Random();

        RequestedInfo ri = ind.getRequestedInfo();

        try {
            MAPDialogMobility mapDialogMobility = ind.getMAPDialog();
            long invokeId = ind.getInvokeId();
            mapDialogMobility.setUserObject(invokeId);
            MAPProvider mapProvider = this.clientMapProvider;

            MAPParameterFactoryImpl mapFactory = new MAPParameterFactoryImpl();

            LocationInformation locationInformation = null;
            LocationInformationEPS locationInformationEPS = null;
            LocationInformationGPRS locationInformationGPRS = null;
            Boolean currentLocationRetrieved = false;
            Boolean saiPresent = null;
            int mcc, mnc, lac, cellId;
            CellGlobalIdOrServiceAreaIdOrLAI cellGlobalIdOrServiceAreaIdOrLAI = null;
            CellGlobalIdOrServiceAreaIdFixedLength cgiOrSai;
            LocationNumber locationNumber = null;
            LocationNumberMap locationNumberMap = null;
            String mscAddress = "5982123007";
            String vlrAddress = "59899000231";
            String sgsnAddress = "5982133021";
            ISDNAddressString mscNumber, vlrNumber, sgsnNumber;
            GeographicalInformation geographicalInformation = null;
            GeodeticInformation geodeticInformation = null;
            EUtranCgi eUtranCgi;
            TAId taId;
            LSAIdentity selectedLSAIdentity = null;
            RAIdentity routeingAreaIdentity = null;
            RouteingNumber routeingNumber = null;
            currentLocationRetrieved = false;
            UserCSGInformation userCSGInformation = null;
            SubscriberStateChoice subscriberStateChoice = null;
            PSSubscriberStateChoice psSubscriberStateChoice = null;
            SubscriberState subscriberState = null;
            PSSubscriberState psSubscriberState = null;
            NotReachableReason notReachableReason = null;
            ArrayList<PDPContextInfo> pdpContextInfoList = null;//new ArrayList<PDPContextInfo>();
            MNPInfoRes mnpInfoRes = null;
            NumberPortabilityStatus numberPortabilityStatus = null;
            MSClassmark2 msClassmark2 = null;
            GPRSMSClass gprsMSClass = null;
            IMEI imei = null;
            MAPExtensionContainer extensionContainer = null;

            if (ri.getLocationInformation()) {
                if (ri.getCurrentLocation()) {
                    currentLocationRetrieved = true;
                }
                int ageOfLocationInformation = 5;
                if (invokeId % 2 == 0)
                    saiPresent = true; // set saiPresent to true if this ATI request is even since test started
                else
                    saiPresent = false; // set saiPresent to false if this ATI request is odd since test started

                TypeOfShape geographicalTypeOfShape = TypeOfShape.EllipsoidPointWithUncertaintyCircle;
                TypeOfShape geodeticTypeOfShape = TypeOfShape.EllipsoidPointWithUncertaintyCircle;
                if (invokeId % 2 == 0) {
                    Double geographicalLatitude = -44.721023;
                    Double geographicalLongitude = 105.993418;
                    Double geographicalUncertainty = 10.0;
                    geographicalInformation = new GeographicalInformationImpl(geographicalTypeOfShape, geographicalLatitude, geographicalLongitude, geographicalUncertainty);
                } else {
                    Double geodeticLatitude = -45.002109;
                    Double geodeticLongitude = 110.100079;
                    Double geodeticlUncertainty = 5.0;
                    int geodeticConfidence = 1;
                    int screeningAndPresentationIndicators = 3;
                    geodeticInformation = new GeodeticInformationImpl(screeningAndPresentationIndicators, geodeticTypeOfShape, geodeticLatitude, geodeticLongitude, geodeticlUncertainty, geodeticConfidence);
                }
                if (ri.getRequestedDomain() == null || ri.getRequestedDomain() == DomainType.csDomain) {
                    mscNumber = new ISDNAddressStringImpl(AddressNature.international_number,NumberingPlan.ISDN, mscAddress);
                    vlrNumber = mapProvider.getMAPParameterFactory().createISDNAddressString(AddressNature.international_number,
                        NumberingPlan.ISDN, vlrAddress);
                    int natureOfAddressIndicator = 4;
                    String locationNumberAddressDigits= "819203961904";
                    int numberingPlanIndicator = 1;
                    int internalNetworkNumberIndicator = 1;
                    int addressRepresentationRestrictedIndicator = 1;
                    int screeningIndicator = 3;
                    locationNumber = new LocationNumberImpl(natureOfAddressIndicator, locationNumberAddressDigits, numberingPlanIndicator,
                        internalNetworkNumberIndicator, addressRepresentationRestrictedIndicator, screeningIndicator);
                    locationNumberMap = null;
                    try {
                        locationNumberMap = new LocationNumberMapImpl(locationNumber);
                    } catch (MAPException e) {
                        e.printStackTrace();
                    }
                    byte[] lteCgi = hexStringToByteArray("37320100014e4a");
                    eUtranCgi = new EUtranCgiImpl(lteCgi);
                    byte[] trackinAreaId = hexStringToByteArray("3732013935");
                    taId = new TAIdImpl(trackinAreaId);
                    String mmneNameStr = "mmec03.mmeer3000.mme.epc.mnc002.mcc748.3gppnetwork.org";
                    byte[] mme = mmneNameStr.getBytes();
                    DiameterIdentity mmeName = new DiameterIdentityImpl(mme);
                    byte[] lsaId = {49, 51, 50};
                    LSAIdentity selectedLSAId = new LSAIdentityImpl(lsaId);
                    userCSGInformation = null;

                    mcc = 748;
                    mnc = 21;
                    lac = 32005;
                    cellId = 38221;
                    cgiOrSai = mapProvider.getMAPParameterFactory().createCellGlobalIdOrServiceAreaIdFixedLength(mcc, mnc, lac, cellId);
                    cellGlobalIdOrServiceAreaIdOrLAI = mapProvider.getMAPParameterFactory().createCellGlobalIdOrServiceAreaIdOrLAI(cgiOrSai);
                    locationInformationEPS = new LocationInformationEPSImpl(eUtranCgi, taId, extensionContainer, geographicalInformation,
                        geodeticInformation, currentLocationRetrieved, ageOfLocationInformation, mmeName);
                    locationInformation = mapProvider.getMAPParameterFactory().createLocationInformation(ageOfLocationInformation, geographicalInformation,
                        vlrNumber, locationNumberMap, cellGlobalIdOrServiceAreaIdOrLAI, extensionContainer, selectedLSAId, mscNumber, geodeticInformation,
                        currentLocationRetrieved, saiPresent, locationInformationEPS, userCSGInformation);
                } else {
                    mcc = 748;
                    mnc = 23;
                    lac = 32006;
                    cellId = 38222;
                    if (invokeId % 2 == 0)
                        saiPresent = true; // set saiPresent to true if this ATI request is even since test started
                    else
                        saiPresent = false; // set saiPresent to false if this ATI request is odd since test started
                    cgiOrSai = mapProvider.getMAPParameterFactory().createCellGlobalIdOrServiceAreaIdFixedLength(mcc, mnc, lac, cellId);
                    cellGlobalIdOrServiceAreaIdOrLAI = mapProvider.getMAPParameterFactory().createCellGlobalIdOrServiceAreaIdOrLAI(cgiOrSai);
                    byte[] raId = hexStringToByteArray("47f810393532");
                    routeingAreaIdentity = new RAIdentityImpl(raId);
                    sgsnNumber = mapProvider.getMAPParameterFactory().createISDNAddressString(AddressNature.international_number,
                        NumberingPlan.ISDN, sgsnAddress);
                    byte[] lsaId = {49, 51, 49};
                    selectedLSAIdentity = new LSAIdentityImpl(lsaId);
                    locationInformationGPRS = mapProvider.getMAPParameterFactory().createLocationInformationGPRS(cellGlobalIdOrServiceAreaIdOrLAI,
                        routeingAreaIdentity, geographicalInformation, sgsnNumber, selectedLSAIdentity, extensionContainer, saiPresent, geodeticInformation,
                        currentLocationRetrieved, ageOfLocationInformation);
                }
            }

            if (ri.getMnpRequestedInfo()) {
                routeingNumber = new RouteingNumberImpl("598123");
                IMSI imsi = new IMSIImpl("748026871012345");
                String msisdnStr = "59899077937";
                ISDNAddressString msisdn = new ISDNAddressStringImpl(AddressNature.international_number,
                    NumberingPlan.ISDN, msisdnStr);
                numberPortabilityStatus = NumberPortabilityStatus.ownNumberNotPortedOut;
                mnpInfoRes = mapProvider.getMAPParameterFactory().createMNPInfoRes(routeingNumber, imsi, msisdn, numberPortabilityStatus, extensionContainer);
            }

            if (ri.getImei()) {
                if (ri.getRequestedDomain() == null || ri.getRequestedDomain() == DomainType.csDomain) {
                    imei = mapProvider.getMAPParameterFactory().createIMEI("011714004661050");
                } else {
                    imei = mapProvider.getMAPParameterFactory().createIMEI("011714004661051");
                }
            }

            if (ri.getMsClassmark()) {
                if (ri.getRequestedDomain() == null || ri.getRequestedDomain() == DomainType.csDomain) {
                    byte[] classmark = {57, 58, 82};
                    msClassmark2 = mapProvider.getMAPParameterFactory().createMSClassmark2(classmark);
                } else {
                    byte[] mSNetworkCapabilityB = hexStringToByteArray("3130303032303331");
                    MSNetworkCapability mSNetworkCapability = new MSNetworkCapabilityImpl(mSNetworkCapabilityB);
                    byte[] mSRadioAccessCapabilityB = hexStringToByteArray("31303030323033313730383134");
                    MSRadioAccessCapability mSRadioAccessCapability = new MSRadioAccessCapabilityImpl(mSRadioAccessCapabilityB);
                    gprsMSClass = mapProvider.getMAPParameterFactory().createGPRSMSClass(mSNetworkCapability, mSRadioAccessCapability);
                }
            }

            Integer stateOption = rand.nextInt(17) + 1;
            switch (stateOption) {
                case 1:
                case 2:
                case 3:
                case 4:
                case 5:
                case 6:
                    subscriberStateChoice = SubscriberStateChoice.assumedIdle;
                    psSubscriberStateChoice = PSSubscriberStateChoice.psAttachedReachableForPaging;
                    break;
                case 7:
                case 8:
                case 9:
                case 10:
                case 11:
                case 12:
                    subscriberStateChoice = SubscriberStateChoice.camelBusy;
                    psSubscriberStateChoice = PSSubscriberStateChoice.psAttachedReachableForPaging;
                    break;
                case 13:
                    subscriberStateChoice = SubscriberStateChoice.netDetNotReachable;
                    notReachableReason = NotReachableReason.imsiDetached;
                    psSubscriberStateChoice = PSSubscriberStateChoice.netDetNotReachable;
                    int ageOfLocationInformation = 1575;
                    currentLocationRetrieved = false;
                    geographicalInformation = null;
                    geodeticInformation = null;
                    locationInformationEPS = null;
                    mscNumber = null;
                    imei = null;
                    msClassmark2 = null;
                    gprsMSClass = null;
                    mnpInfoRes = null;
                    if (ri.getRequestedDomain() == null || ri.getRequestedDomain() == DomainType.csDomain) {
                        vlrNumber = mapProvider.getMAPParameterFactory().createISDNAddressString(AddressNature.international_number,
                            NumberingPlan.ISDN, vlrAddress);
                        locationInformation = mapProvider.getMAPParameterFactory().createLocationInformation(ageOfLocationInformation, geographicalInformation,
                            vlrNumber, locationNumberMap, cellGlobalIdOrServiceAreaIdOrLAI, extensionContainer, selectedLSAIdentity, mscNumber, geodeticInformation,
                            currentLocationRetrieved, saiPresent, locationInformationEPS, userCSGInformation);
                    } else {
                        sgsnNumber = mapProvider.getMAPParameterFactory().createISDNAddressString(AddressNature.international_number,
                            NumberingPlan.ISDN, sgsnAddress);
                        locationInformationGPRS = mapProvider.getMAPParameterFactory().createLocationInformationGPRS(cellGlobalIdOrServiceAreaIdOrLAI,
                            routeingAreaIdentity, geographicalInformation, sgsnNumber, selectedLSAIdentity, extensionContainer, saiPresent, geodeticInformation,
                            currentLocationRetrieved, ageOfLocationInformation);
                    }
                    break;
                case 14:
                case 15:
                    subscriberStateChoice = SubscriberStateChoice.notProvidedFromVLR;
                    psSubscriberStateChoice = PSSubscriberStateChoice.notProvidedFromSGSNorMME;
                    break;
                case 16:
                    subscriberStateChoice = SubscriberStateChoice.netDetNotReachable;
                    notReachableReason = NotReachableReason.restrictedArea;
                    psSubscriberStateChoice = PSSubscriberStateChoice.netDetNotReachable;
                    ageOfLocationInformation = 300;
                    currentLocationRetrieved = false;
                    geographicalInformation = null;
                    geodeticInformation = null;
                    locationInformationEPS = null;
                    mscNumber = null;
                    imei = null;
                    msClassmark2 = null;
                    gprsMSClass = null;
                    mnpInfoRes = null;
                    if (ri.getRequestedDomain() == null || ri.getRequestedDomain() == DomainType.csDomain) {
                        vlrNumber = mapProvider.getMAPParameterFactory().createISDNAddressString(AddressNature.international_number,
                            NumberingPlan.ISDN, vlrAddress);
                        locationInformation = mapProvider.getMAPParameterFactory().createLocationInformation(ageOfLocationInformation, geographicalInformation,
                            vlrNumber, locationNumberMap, cellGlobalIdOrServiceAreaIdOrLAI, extensionContainer, selectedLSAIdentity, mscNumber, geodeticInformation,
                            currentLocationRetrieved, saiPresent, locationInformationEPS, userCSGInformation);
                    } else  {
                        sgsnNumber = mapProvider.getMAPParameterFactory().createISDNAddressString(AddressNature.international_number,
                            NumberingPlan.ISDN, sgsnAddress);
                        locationInformationGPRS = mapProvider.getMAPParameterFactory().createLocationInformationGPRS(cellGlobalIdOrServiceAreaIdOrLAI,
                            routeingAreaIdentity, geographicalInformation, sgsnNumber, selectedLSAIdentity, extensionContainer, saiPresent, geodeticInformation,
                            currentLocationRetrieved, ageOfLocationInformation);
                    }
                    break;
                case 17:
                    subscriberStateChoice = SubscriberStateChoice.netDetNotReachable;
                    notReachableReason = NotReachableReason.msPurged;
                    psSubscriberStateChoice = PSSubscriberStateChoice.psAttachedNotReachableForPaging;
                    ageOfLocationInformation = 221;
                    currentLocationRetrieved = false;
                    geographicalInformation = null;
                    geodeticInformation = null;
                    locationInformationEPS = null;
                    mscNumber = null;
                    imei = null;
                    msClassmark2 = null;
                    gprsMSClass = null;
                    mnpInfoRes = null;
                    if (ri.getRequestedDomain() == null || ri.getRequestedDomain() == DomainType.csDomain) {
                        vlrNumber = mapProvider.getMAPParameterFactory().createISDNAddressString(AddressNature.international_number,
                            NumberingPlan.ISDN, vlrAddress);
                        locationInformation = mapProvider.getMAPParameterFactory().createLocationInformation(ageOfLocationInformation, geographicalInformation,
                            vlrNumber, locationNumberMap, cellGlobalIdOrServiceAreaIdOrLAI, extensionContainer, selectedLSAIdentity, mscNumber, geodeticInformation,
                            currentLocationRetrieved, saiPresent, locationInformationEPS, userCSGInformation);
                    } else {
                        sgsnNumber = mapProvider.getMAPParameterFactory().createISDNAddressString(AddressNature.international_number,
                            NumberingPlan.ISDN, sgsnAddress);
                        locationInformationGPRS = mapProvider.getMAPParameterFactory().createLocationInformationGPRS(cellGlobalIdOrServiceAreaIdOrLAI,
                            routeingAreaIdentity, geographicalInformation, sgsnNumber, selectedLSAIdentity, extensionContainer, saiPresent, geodeticInformation,
                            currentLocationRetrieved, ageOfLocationInformation);
                    }
                    break;
            }
            if (ri.getSubscriberState()) {
                if (ri.getRequestedDomain() == null || ri.getRequestedDomain() == DomainType.csDomain) {
                    subscriberState = mapProvider.getMAPParameterFactory().createSubscriberState(subscriberStateChoice, notReachableReason);
                } else {
                    psSubscriberState = mapProvider.getMAPParameterFactory().createPSSubscriberState(psSubscriberStateChoice, notReachableReason, pdpContextInfoList);
                }
            }

            SubscriberInfo subscriberInfo = mapProvider.getMAPParameterFactory().createSubscriberInfo(locationInformation, subscriberState, extensionContainer,
                locationInformationGPRS, psSubscriberState, imei, msClassmark2, gprsMSClass, mnpInfoRes);

            mapDialogMobility.addAnyTimeInterrogationResponse(invokeId, subscriberInfo, extensionContainer);

            // This will initiate the TC-BEGIN with INVOKE component
            mapDialogMobility.close(false);

        } catch (MAPException mapException) {
            logger.error("MAP Exception while processing AnyTimeInterrogationRequest ", mapException);
        } catch (Exception e) {
            logger.error("Exception while processing AnyTimeInterrogationRequest ", e);
        }

    }

    @Override
    public void onAnyTimeInterrogationResponse(AnyTimeInterrogationResponse atiResp) {

        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onAnyTimeInterrogationResponse  for DialogId=%d",
                atiResp.getMAPDialog().getLocalDialogId()));
        } else {
            logger.info(String.format("onAnyTimeInterrogationResponse  for DialogId=%d",
                atiResp.getMAPDialog().getLocalDialogId()));
        }

        try {

            SubscriberInfo si = atiResp.getSubscriberInfo();

            if (si != null) {

                if (si.getLocationInformation() != null) {

                    if (si.getLocationInformation().getCellGlobalIdOrServiceAreaIdOrLAI() != null) {
                        CellGlobalIdOrServiceAreaIdOrLAI cellGlobalIdOrServiceAreaIdOrLAI = si.getLocationInformation()
                            .getCellGlobalIdOrServiceAreaIdOrLAI();

                        if (cellGlobalIdOrServiceAreaIdOrLAI.getCellGlobalIdOrServiceAreaIdFixedLength() != null) {
                            int mcc = cellGlobalIdOrServiceAreaIdOrLAI.getCellGlobalIdOrServiceAreaIdFixedLength().getMCC();
                            int mnc = cellGlobalIdOrServiceAreaIdOrLAI.getCellGlobalIdOrServiceAreaIdFixedLength().getMNC();
                            int lac = cellGlobalIdOrServiceAreaIdOrLAI.getCellGlobalIdOrServiceAreaIdFixedLength().getLac();
                            int cellId = cellGlobalIdOrServiceAreaIdOrLAI.getCellGlobalIdOrServiceAreaIdFixedLength()
                                .getCellIdOrServiceAreaCode();
                            if (logger.isDebugEnabled()) {
                                logger.debug(String.format(
                                    "Rx onAnyTimeInterrogationResponse:  CI=%d, LAC=%d, MNC=%d, MCC=%d, for DialogId=%d",
                                    cellId, lac, mnc, mcc, atiResp.getMAPDialog().getLocalDialogId()));
                            } else {
                                logger.info(String.format(
                                    "Rx onAnyTimeInterrogationResponse:  CI=%d, LAC=%d, MNC=%d, MCC=%d, for DialogId=%d",
                                    cellId, lac, mnc, mcc, atiResp.getMAPDialog().getLocalDialogId()));
                            }
                        }
                    }

                    if (si.getLocationInformation().getLocationNumber() != null) {
                        if (si.getLocationInformation().getLocationNumber().getLocationNumber() != null) {
                            if (this.logger.isDebugEnabled()) {
                                this.logger.debug("\nRx onAnyTimeInterrogationResponse:: Location Number is included: "+si.getLocationInformation().getLocationNumber().getLocationNumber().toString());
                            }
                        }
                    }

                    if (si.getLocationInformation().getGeographicalInformation() != null) {
                        if (this.logger.isDebugEnabled()) {
                            this.logger.debug("\nRx onAnyTimeInterrogationResponse:: geographical information is included: "+new String(si.getLocationInformation().getGeographicalInformation().getData()));
                        }
                    }

                    if (si.getLocationInformation().getGeodeticInformation() != null) {
                        if (this.logger.isDebugEnabled()) {
                            this.logger.debug("\nRx onAnyTimeInterrogationResponse:: geodetic information is included: "+new String(si.getLocationInformation().getGeodeticInformation().getData()));
                        }
                    }

                    if (si.getLocationInformation().getAgeOfLocationInformation() != null) {
                        int aol = si.getLocationInformation().getAgeOfLocationInformation().intValue();
                        if (logger.isDebugEnabled()) {
                            logger.debug(String.format("Rx onAnyTimeInterrogationResponse: AoL=%d for DialogId=%d", aol,
                                atiResp.getMAPDialog().getLocalDialogId()));
                        } else {
                            logger.info(String.format("Rx onAnyTimeInterrogationResponse: AoL=%d for DialogId=%d", aol,
                                atiResp.getMAPDialog().getLocalDialogId()));
                        }
                    }

                    if (si.getLocationInformation().getVlrNumber() != null) {
                        String vlrAddress = si.getLocationInformation().getVlrNumber().getAddress();
                        if (logger.isDebugEnabled()) {
                            logger.debug(String.format("Rx onAnyTimeInterrogationResponse: VLR address=%s for DialogId=%d",
                                vlrAddress, atiResp.getMAPDialog().getLocalDialogId()));
                        } else {
                            logger.info(String.format("Rx onAnyTimeInterrogationResponse: VLR address=%s for DialogId=%d",
                                vlrAddress, atiResp.getMAPDialog().getLocalDialogId()));
                        }
                    }
                    if (si.getLocationInformation().getMscNumber() != null) {
                        String vlrAddress = si.getLocationInformation().getMscNumber().getAddress();
                        if (logger.isDebugEnabled()) {
                            logger.debug(String.format("Rx onAnyTimeInterrogationResponse: MSC address=%s for DialogId=%d",
                                vlrAddress, atiResp.getMAPDialog().getLocalDialogId()));
                        } else {
                            logger.info(String.format("Rx onAnyTimeInterrogationResponse: MSC address=%s for DialogId=%d",
                                vlrAddress, atiResp.getMAPDialog().getLocalDialogId()));
                        }
                    }

                    if (si.getLocationInformation().getCurrentLocationRetrieved()) {
                        if (this.logger.isDebugEnabled()) {
                            this.logger.debug("\nRx onAnyTimeInterrogationResponse: current location retrieved");
                        }
                    }

                    if (si.getLocationInformation().getSaiPresent()) {
                        if (this.logger.isDebugEnabled()) {
                            this.logger.debug("\nRx onAnyTimeInterrogationResponse: SAI present");
                        }
                    }

                    if (si.getLocationInformation().getLocationInformationEPS() != null) {
                        if (si.getLocationInformation().getLocationInformationEPS().getEUtranCellGlobalIdentity() != null) {
                            if (logger.isDebugEnabled()) {
                                logger.debug(String.format("Rx onAnyTimeInterrogationResponse: ECGI=%s for DialogId=%d",
                                    new String(si.getLocationInformation().getLocationInformationEPS().getEUtranCellGlobalIdentity().getData()),
                                    atiResp.getMAPDialog().getLocalDialogId()));
                            }
                        }
                        if (si.getLocationInformation().getLocationInformationEPS().getTrackingAreaIdentity() != null) {
                            if (logger.isDebugEnabled()) {
                                logger.debug(String.format("Rx onAnyTimeInterrogationResponse: TAI=%s for DialogId=%d",
                                    new String(si.getLocationInformation().getLocationInformationEPS().getTrackingAreaIdentity().getData()),
                                    atiResp.getMAPDialog().getLocalDialogId()));
                            }
                        }
                        if (si.getLocationInformation().getLocationInformationEPS().getGeographicalInformation() != null) {
                            if (logger.isDebugEnabled()) {
                                logger.debug(String.format("Rx onAnyTimeInterrogationResponse: geographical information=%s for DialogId=%d",
                                    new String(si.getLocationInformation().getLocationInformationEPS().getGeographicalInformation().getData()),
                                    atiResp.getMAPDialog().getLocalDialogId()));
                            }
                        }
                        if (si.getLocationInformation().getLocationInformationEPS().getGeodeticInformation() != null) {
                            if (logger.isDebugEnabled()) {
                                logger.debug(String.format("Rx onAnyTimeInterrogationResponse: geodetic information=%s for DialogId=%d",
                                    new String(si.getLocationInformation().getLocationInformationEPS().getGeodeticInformation().getData()),
                                    atiResp.getMAPDialog().getLocalDialogId()));
                            }
                        }
                    }
                }

                if (si.getSubscriberState() != null) {
                    if (logger.isDebugEnabled()) {
                        logger.debug(String.format("Rx onAnyTimeInterrogationResponse SubscriberState: "
                            + si.getSubscriberState() + "for DialogId=%d", atiResp.getMAPDialog().getLocalDialogId()));
                    } else {
                        logger.info(String.format("Rx onAnyTimeInterrogationResponse SubscriberState: "
                            + si.getSubscriberState() + "for DialogId=%d", atiResp.getMAPDialog().getLocalDialogId()));
                    }
                } else {
                    if (logger.isDebugEnabled()) {
                        logger.debug(String.format(
                            "Rx onAnyTimeInterrogationResponse, Incorrect Subscriber State received: " + si + "for DialogId=%d",
                            atiResp.getMAPDialog().getLocalDialogId()));
                    } else {
                        logger.info(String.format(
                            "Rx onAnyTimeInterrogationResponse, Incorrect Subscriber State received: " + si + "for DialogId=%d",
                            atiResp.getMAPDialog().getLocalDialogId()));
                    }
                }

                if (si.getMNPInfoRes() != null) {
                    if (logger.isDebugEnabled()) {
                        logger.debug(String.format("Rx onAnyTimeInterrogationResponse MNPInfoResult: "
                            + si.getMNPInfoRes().toString() + "for DialogId=%d", atiResp.getMAPDialog().getLocalDialogId()));
                    }
                }

                if (si.getLocationInformationGPRS() != null) {
                    if (si.getLocationInformationGPRS().getSGSNNumber() != null) {
                        if (logger.isDebugEnabled()) {
                            logger.debug(String.format("Rx onAnyTimeInterrogationResponse SGSN number: "
                                + si.getLocationInformationGPRS().getSGSNNumber().getAddress() + "for DialogId=%d", atiResp.getMAPDialog().getLocalDialogId()));
                        }
                    }
                    if (si.getLocationInformationGPRS().getRouteingAreaIdentity() != null) {
                        if (logger.isDebugEnabled()) {
                            logger.debug(String.format("Rx onAnyTimeInterrogationResponse RAI: "
                                    + new String(si.getLocationInformationGPRS().getRouteingAreaIdentity().getData()) + "for DialogId=%d",
                                atiResp.getMAPDialog().getLocalDialogId()));
                        }
                    }
                    if (si.getLocationInformationGPRS().getLSAIdentity() != null) {
                        if (logger.isDebugEnabled()) {
                            logger.debug(String.format("Rx onAnyTimeInterrogationResponse LSAId: "
                                    + new String(si.getLocationInformationGPRS().getLSAIdentity().getData()) + "for DialogId=%d",
                                atiResp.getMAPDialog().getLocalDialogId()));
                        }
                    }
                    if (si.getLocationInformationGPRS().getGeographicalInformation() != null) {
                        if (logger.isDebugEnabled()) {
                            logger.debug(String.format("Rx onAnyTimeInterrogationResponse: geographical information=%s for DialogId=%d",
                                new String(si.getLocationInformationGPRS().getGeographicalInformation().getData()),
                                atiResp.getMAPDialog().getLocalDialogId()));
                        }
                    }
                    if (si.getLocationInformationGPRS().getGeodeticInformation() != null) {
                        if (logger.isDebugEnabled()) {
                            logger.debug(String.format("Rx onAnyTimeInterrogationResponse: geodetic information=%s for DialogId=%d",
                                new String(si.getLocationInformationGPRS().getGeodeticInformation().getData()),
                                atiResp.getMAPDialog().getLocalDialogId()));
                        }
                    }
                    if (si.getLocationInformationGPRS().getAgeOfLocationInformation() != null) {
                        if (logger.isDebugEnabled()) {
                            logger.debug(String.format("Rx onAnyTimeInterrogationResponse AoL: "
                                + si.getLocationInformationGPRS().getAgeOfLocationInformation().intValue() + "for DialogId=%d", atiResp.getMAPDialog().getLocalDialogId()));
                        }
                    }
                }

            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format("Bad AnyTimeInterrogationResponse received: " + atiResp + "for DialogId=%d",
                        atiResp.getMAPDialog().getLocalDialogId()));
                } else {
                    logger.info(String.format("Bad AnyTimeInterrogationResponse received: " + atiResp + "for DialogId=%d",
                        atiResp.getMAPDialog().getLocalDialogId()));
                }
            }

        } catch (Exception e) {
            logger.error(String.format("Error while processing onAnyTimeInterrogationResponse for Dialog=%d",
                atiResp.getMAPDialog().getLocalDialogId(), ", Exception: " + e.getStackTrace()));

        }
    }

    @Override
    public void onAnyTimeSubscriptionInterrogationRequest(AnyTimeSubscriptionInterrogationRequest request) {

    }

    @Override
    public void onAnyTimeSubscriptionInterrogationResponse(AnyTimeSubscriptionInterrogationResponse response) {

    }

    @Override
    public void onSendRoutingInfoForLCSRequest(SendRoutingInfoForLCSRequest sendRoutingInforForLCSRequest) {

        if (logger.isDebugEnabled()) {
            logger.debug(
                String.format("onSendRoutingInfoForLCSRequest for DialogId=%d", sendRoutingInforForLCSRequest.getMAPDialog().getLocalDialogId()));
        }
        if (logger.isInfoEnabled()) {
            logger.info(String.format("onAnyTimeInterrogationRequest for DialogId=%d", sendRoutingInforForLCSRequest.getMAPDialog().getLocalDialogId()));
        }

        try {
            long invokeId = sendRoutingInforForLCSRequest.getInvokeId();
            MAPDialogLsm mapDialogLsm = sendRoutingInforForLCSRequest.getMAPDialog();
            mapDialogLsm.setUserObject(invokeId);

            // Create Routing Information parameters for concerning MAP operation
            MAPParameterFactoryImpl mapFactory = new MAPParameterFactoryImpl();
            String mscAddress = "5982123007";
            String sgsnAddress = "5982123009";
            ISDNAddressString mscNumber = new ISDNAddressStringImpl(AddressNature.international_number,
                NumberingPlan.ISDN, mscAddress);
            ISDNAddressString sgsnNumber = new ISDNAddressStringImpl(AddressNature.international_number,
                NumberingPlan.ISDN, sgsnAddress);
            AdditionalNumber additionalNumber = new AdditionalNumberImpl(null, sgsnNumber);
            String lmsiStr = "12345678";
            byte[] Lmsi = lmsiStr.getBytes();
            LMSI lmsi = mapFactory.createLMSI(Lmsi);
            Boolean gprsNodeIndicator = false;
            boolean lcsCapabilitySetRelease98_99 = true;
            boolean lcsCapabilitySetRelease4 = true;
            boolean lcsCapabilitySetRelease5 = true;
            boolean lcsCapabilitySetRelease6 = true;
            boolean lcsCapabilitySetRelease7 = false;
            SupportedLCSCapabilitySets supportedLCSCapabilitySets = new SupportedLCSCapabilitySetsImpl(lcsCapabilitySetRelease98_99, lcsCapabilitySetRelease4,
                lcsCapabilitySetRelease5, lcsCapabilitySetRelease6, lcsCapabilitySetRelease7);
            lcsCapabilitySetRelease7 = true;
            SupportedLCSCapabilitySets additionalLCSCapabilitySets = new SupportedLCSCapabilitySetsImpl(lcsCapabilitySetRelease98_99, lcsCapabilitySetRelease4,
                lcsCapabilitySetRelease5, lcsCapabilitySetRelease6, lcsCapabilitySetRelease7);
            MAPExtensionContainer mapExtensionContainer = null;
            byte[] mmeNom = new BigInteger("00112233445566778899", 16).toByteArray();
            DiameterIdentity mmeName = new DiameterIdentityImpl(mmeNom);
            byte[] aaaSN = new BigInteger("0011223344556677889900", 16).toByteArray();
            DiameterIdentity aaaServerName = new DiameterIdentityImpl(aaaSN);
            ISDNAddressString isdnAdd = new ISDNAddressStringImpl(AddressNature.international_number,
                NumberingPlan.ISDN, "59899077937");
            SubscriberIdentity msisdn = new SubscriberIdentityImpl(isdnAdd);
            byte[] visitedGmlcAddress = new BigInteger("112233445500", 16).toByteArray();
            GSNAddress vGmlcAddress = new GSNAddressImpl(visitedGmlcAddress);
            byte[] homeGmlcAddress = new BigInteger("11223344556677", 16).toByteArray();
            GSNAddress hGmlcAddress = new GSNAddressImpl(homeGmlcAddress);
            byte[] pivacyProfileRegisterAddress = new BigInteger("112233445566", 16).toByteArray();
            GSNAddress pprAddress = new GSNAddressImpl(pivacyProfileRegisterAddress);
            byte[] addVGmlcAddress = new BigInteger("5522334455", 16).toByteArray();
            GSNAddress additionalVGmlcAddress = new GSNAddressImpl(addVGmlcAddress);

            LCSLocationInfo lcsLocationInfo = mapFactory.createLCSLocationInfo(mscNumber, lmsi, mapExtensionContainer, gprsNodeIndicator,
                additionalNumber, supportedLCSCapabilitySets, additionalLCSCapabilitySets, mmeName, aaaServerName);
//            addSendRoutingInfoForLCSResponse(long invokeId, SubscriberIdentity targetMS, LCSLocationInfo lcsLocationInfo,
//                                             MAPExtensionContainer extensionContainer,
//                                            byte[] vgmlcAddress, byte[] hGmlcAddress, byte[] pprAddress, byte[] additionalVGmlcAddress)
            mapDialogLsm.addSendRoutingInfoForLCSResponse(invokeId, msisdn, lcsLocationInfo, mapExtensionContainer, vGmlcAddress, hGmlcAddress,
                pprAddress, additionalVGmlcAddress);
            // This will initiate the TC-BEGIN with INVOKE component
            mapDialogLsm.close(false);

        } catch (MAPException mapException) {
            logger.error("MAP Exception while processing onSendRoutingInfoForLCSRequest ", mapException);
        } catch (Exception e) {
            logger.error("Exception while processing onSendRoutingInfoForLCSRequest ", e);
        }
    }

    @Override
    public void onSendRoutingInfoForLCSResponse(SendRoutingInfoForLCSResponse sendRoutingInforForLCSResponse) {

        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onSendRoutingInfoForLCSResponse  for DialogId=%d",
                sendRoutingInforForLCSResponse.getMAPDialog().getLocalDialogId()));
        } else {
            logger.info(String.format("onSendRoutingInfoForLCSResponse  for DialogId=%d",
                sendRoutingInforForLCSResponse.getMAPDialog().getLocalDialogId()));
        }

        try {

            LCSLocationInfo lcsLocationInfo = sendRoutingInforForLCSResponse.getLCSLocationInfo();

            if (lcsLocationInfo != null) {

                if (lcsLocationInfo.getNetworkNodeNumber() != null) {
                    String networkNodeNumber = lcsLocationInfo.getNetworkNodeNumber().toString();
                    if (logger.isDebugEnabled()) {
                        logger.debug(String.format("Rx onSendRoutingInfoForLCSResponse NetworkNodeNumber = " + networkNodeNumber +
                            "for DialogId=%d", sendRoutingInforForLCSResponse.getMAPDialog().getLocalDialogId()));
                    } else {
                        logger.info(String.format("Rx onSendRoutingInfoForLCSResponse NetworkNodeNumber: "
                            + lcsLocationInfo.getNetworkNodeNumber() + "for DialogId=%d", sendRoutingInforForLCSResponse.getMAPDialog().getLocalDialogId()));
                    }
                } else {
                    if (logger.isDebugEnabled()) {
                        logger.debug(String.format(
                            "Rx onSendRoutingInfoForLCSResponse, Incorrect NetworkNodeNumber received: " + lcsLocationInfo + "for DialogId=%d",
                            sendRoutingInforForLCSResponse.getMAPDialog().getLocalDialogId()));
                    } else {
                        logger.info(String.format(
                            "Rx onSendRoutingInfoForLCSResponse, Incorrect NetworkNodeNumber received: " + lcsLocationInfo + "for DialogId=%d",
                            sendRoutingInforForLCSResponse.getMAPDialog().getLocalDialogId()));
                    }
                }

                if (lcsLocationInfo.getLMSI() != null) {
                    String lmsi = lcsLocationInfo.getLMSI().toString();
                    if (logger.isDebugEnabled()) {
                        logger.debug(String.format("Rx onSendRoutingInfoForLCSResponse LMSI = " + lmsi +
                            "for DialogId=%d", sendRoutingInforForLCSResponse.getMAPDialog().getLocalDialogId()));
                    } else {
                        logger.info(String.format("Rx onSendRoutingInfoForLCSResponse LMSI: "
                            + lcsLocationInfo.getLMSI() + "for DialogId=%d", sendRoutingInforForLCSResponse.getMAPDialog().getLocalDialogId()));
                    }
                } else {
                    if (logger.isDebugEnabled()) {
                        logger.debug(String.format(
                            "Rx onSendRoutingInfoForLCSResponse, Incorrect LMSI received: " + lcsLocationInfo + "for DialogId=%d",
                            sendRoutingInforForLCSResponse.getMAPDialog().getLocalDialogId()));
                    } else {
                        logger.info(String.format(
                            "Rx onSendRoutingInfoForLCSResponse, Incorrect LMSI received: " + lcsLocationInfo + "for DialogId=%d",
                            sendRoutingInforForLCSResponse.getMAPDialog().getLocalDialogId()));
                    }
                }

                if (lcsLocationInfo.getSupportedLCSCapabilitySets() != null) {
                    String supportedLCSCapabilitySets = lcsLocationInfo.getSupportedLCSCapabilitySets().toString();
                    if (logger.isDebugEnabled()) {
                        logger.debug(String.format("Rx onSendRoutingInfoForLCSResponse Supported LCS Capability Sets = " + supportedLCSCapabilitySets +
                            "for DialogId=%d", sendRoutingInforForLCSResponse.getMAPDialog().getLocalDialogId()));
                    } else {
                        logger.info(String.format("Rx onSendRoutingInfoForLCSResponse Supported LCS Capability Sets: "
                            + lcsLocationInfo.getSupportedLCSCapabilitySets() + "for DialogId=%d", sendRoutingInforForLCSResponse.getMAPDialog().getLocalDialogId()));
                    }
                } else {
                    if (logger.isDebugEnabled()) {
                        logger.debug(String.format(
                            "Rx onSendRoutingInfoForLCSResponse, Incorrect Supported LCS Capability Sets received: " + lcsLocationInfo + "for DialogId=%d",
                            sendRoutingInforForLCSResponse.getMAPDialog().getLocalDialogId()));
                    } else {
                        logger.info(String.format(
                            "Rx onSendRoutingInfoForLCSResponse, Incorrect Supported LCS Capability Sets received: " + lcsLocationInfo + "for DialogId=%d",
                            sendRoutingInforForLCSResponse.getMAPDialog().getLocalDialogId()));
                    }
                }

                if (lcsLocationInfo.getAdditionalLCSCapabilitySets() != null) {
                    String additionalLCSCapabilitySets = lcsLocationInfo.getAdditionalLCSCapabilitySets().toString();
                    if (logger.isDebugEnabled()) {
                        logger.debug(String.format("Rx onSendRoutingInfoForLCSResponse Additional LCS Capability Sets = " + additionalLCSCapabilitySets +
                            "for DialogId=%d", sendRoutingInforForLCSResponse.getMAPDialog().getLocalDialogId()));
                    } else {
                        logger.info(String.format("Rx onSendRoutingInfoForLCSResponse Additional LCS Capability Sets: "
                            + lcsLocationInfo.getAdditionalLCSCapabilitySets() + "for DialogId=%d", sendRoutingInforForLCSResponse.getMAPDialog().getLocalDialogId()));
                    }
                } else {
                    if (logger.isDebugEnabled()) {
                        logger.debug(String.format(
                            "Rx onSendRoutingInfoForLCSResponse, Incorrect Additional LCS Capability Sets received: " + lcsLocationInfo + "for DialogId=%d",
                            sendRoutingInforForLCSResponse.getMAPDialog().getLocalDialogId()));
                    } else {
                        logger.info(String.format(
                            "Rx onSendRoutingInfoForLCSResponse, Incorrect Additional LCS Capability Sets received: " + lcsLocationInfo + "for DialogId=%d",
                            sendRoutingInforForLCSResponse.getMAPDialog().getLocalDialogId()));
                    }
                }

                if (lcsLocationInfo.getAdditionalNumber() != null) {
                    String sgsnNumber = lcsLocationInfo.getAdditionalNumber().getSGSNNumber().toString();
                    String mscNumber = lcsLocationInfo.getAdditionalNumber().getSGSNNumber().toString();
                    if (logger.isDebugEnabled()) {
                        logger.debug(String.format("Rx Additional Number onSendRoutingInfoForLCSResponse, " +
                            "SGSN Number = " + sgsnNumber + ", MSC Number: " + mscNumber +
                            "for DialogId=%d", sendRoutingInforForLCSResponse.getMAPDialog().getLocalDialogId()));
                    } else {
                        logger.info(String.format("Rx Additional Number onSendRoutingInfoForLCSResponse, " +
                            "SGSN Number: " + sgsnNumber + ", MSC Number: " + mscNumber +
                            "for DialogId=%d", sendRoutingInforForLCSResponse.getMAPDialog().getLocalDialogId()));
                    }
                } else {
                    if (logger.isDebugEnabled()) {
                        logger.debug(String.format(
                            "Rx onSendRoutingInfoForLCSResponse, Incorrect Additional Number received for DialogId=%d",
                            sendRoutingInforForLCSResponse.getMAPDialog().getLocalDialogId()));
                    } else {
                        logger.info(String.format(
                            "Rx onSendRoutingInfoForLCSResponse, Incorrect Additional Number received for DialogId=%d",
                            sendRoutingInforForLCSResponse.getMAPDialog().getLocalDialogId()));
                    }
                }

                if (lcsLocationInfo.getGprsNodeIndicator() != true) {
                    String gprsNodeIndicator = "false";
                    if (logger.isDebugEnabled()) {
                        logger.debug(String.format("Rx onSendRoutingInfoForLCSResponse GPRS Node Indicator = " + gprsNodeIndicator +
                            "for DialogId=%d", sendRoutingInforForLCSResponse.getMAPDialog().getLocalDialogId()));
                    } else {
                        gprsNodeIndicator = "true";
                        logger.info(String.format("Rx onSendRoutingInfoForLCSResponse GPRS Node Indicator = " + gprsNodeIndicator +
                            "for DialogId=%d", sendRoutingInforForLCSResponse.getMAPDialog().getLocalDialogId()));
                    }
                } else {
                    if (logger.isDebugEnabled()) {
                        logger.debug(String.format(
                            "Rx onSendRoutingInfoForLCSResponse, Incorrect GPRS Node Indicator received: " + lcsLocationInfo + "for DialogId=%d",
                            sendRoutingInforForLCSResponse.getMAPDialog().getLocalDialogId()));
                    } else {
                        logger.info(String.format(
                            "Rx onSendRoutingInfoForLCSResponse, Incorrect GPRS Node Indicator received: " + lcsLocationInfo + "for DialogId=%d",
                            sendRoutingInforForLCSResponse.getMAPDialog().getLocalDialogId()));
                    }
                }
            }

        } catch (Exception e) {
            logger.error(String.format("Error while processing onSendRoutingInfoForLCSResponse for Dialog=%d",
                sendRoutingInforForLCSResponse.getMAPDialog().getLocalDialogId()));
        }
    }

    @Override
    public void onProvideSubscriberLocationRequest(ProvideSubscriberLocationRequest provideSubscriberLocationRequest) {

        if (logger.isDebugEnabled()) {
            logger.debug(
                String.format("onProvideSubscriberLocationRequest for DialogId=%d", provideSubscriberLocationRequest.getMAPDialog().getLocalDialogId()));
        }
        if (logger.isInfoEnabled()) {
            logger.info(String.format("onProvideSubscriberLocationRequest for DialogId=%d", provideSubscriberLocationRequest.getMAPDialog().getLocalDialogId()));
        }

        try {
            long invokeId = provideSubscriberLocationRequest.getInvokeId();
            MAPDialogLsm mapDialogLsm = provideSubscriberLocationRequest.getMAPDialog();
            mapDialogLsm.setUserObject(invokeId);

            // Create Routing Information parameters for concerning MAP operation
            MAPParameterFactoryImpl mapFactory = new MAPParameterFactoryImpl();
            ISDNAddressString mscNumber = new ISDNAddressStringImpl(AddressNature.international_number,
                NumberingPlan.ISDN, "5982123007");
            ISDNAddressString sgsnNumber = new ISDNAddressStringImpl(AddressNature.international_number,
                NumberingPlan.ISDN, "5982123009");
            String lmsiStr = "87654321";
            byte[] Lmsi = lmsiStr.getBytes();
            LMSI lmsi = mapFactory.createLMSI(Lmsi);
            byte[] eGeographicalInformation = new BigInteger("014321a10022337799", 16).toByteArray();
            ExtGeographicalInformation extGeographicalInformation = mapFactory.createExtGeographicalInformation(eGeographicalInformation);
            String posDataInfo = "5533ab01";
            byte[] posDataInformation = posDataInfo.getBytes();
            PositioningDataInformation positioningDataInformation = mapFactory.createPositioningDataInformation(posDataInformation);
            byte[] utranData = new BigInteger("43210987654321", 16).toByteArray();
            UtranPositioningDataInfo utranPositioningDataInfo = new UtranPositioningDataInfoImpl(utranData);
            Integer ageOfLocationEstimate = 1;
            byte[] addLocationEstimate = new BigInteger("5533a100223377", 16).toByteArray();
            AddGeographicalInformation additionalLocationEstimate = mapFactory.createAddGeographicalInformation(addLocationEstimate);
/*
            long[] oid = {0, 0, 17, 773, 1, 1, 1};
            String privExtData = "1144";
            byte[] privateExtData = privExtData.getBytes();
            MAPPrivateExtension mapPrivateExtension = new MAPPrivateExtensionImpl(oid, privateExtData);
            ArrayList<MAPPrivateExtension> mapPrivateExtensions = new ArrayList<MAPPrivateExtension>();
            mapPrivateExtensions.add(mapPrivateExtension);
            String pcsExts = "1033";
            byte[] pcsExtensions = pcsExts.getBytes();
            MAPExtensionContainer mapExtensionContainer = new MAPExtensionContainerImpl(mapPrivateExtensions, pcsExtensions);
*/
            MAPExtensionContainer mapExtensionContainer = null;
            Boolean deferredMTLRResponseIndicator = true;
            int mcc, mnc, lac, cellIdOrServiceAreaCode;
            mcc = 748;
            mnc = 1;
            lac = 23;
            cellIdOrServiceAreaCode = 369;
            CellGlobalIdOrServiceAreaIdFixedLength cellGlobalIdOrServiceAreaIdFixedLength = mapFactory
                .createCellGlobalIdOrServiceAreaIdFixedLength(mcc, mnc, lac, cellIdOrServiceAreaCode);
            CellGlobalIdOrServiceAreaIdOrLAI cellGlobalIdOrServiceAreaIdOrLAI = mapFactory
                .createCellGlobalIdOrServiceAreaIdOrLAI(cellGlobalIdOrServiceAreaIdFixedLength);
            Boolean saiPresent = true;
            AccuracyFulfilmentIndicator accuracyFulfilmentIndicator = AccuracyFulfilmentIndicator.getAccuracyFulfilmentIndicator(0);
            // AccuracyFulfilmentIndicator ::= ENUMERATED { requestedAccuracyFulfilled (0), requestedAccuracyNotFulfilled (1), ... }
            String velEstStr = "00000001";
            byte[] velEst = velEstStr.getBytes();
            VelocityEstimate velocityEstimate = mapFactory.createVelocityEstimate(velEst);
            Boolean moLrShortCircuitIndicator = true;
            byte[] gGanss = new BigInteger("666601019999", 16).toByteArray();
            GeranGANSSpositioningData geranGANSSpositioningData = new GeranGANSSpositioningDataImpl(gGanss);
            byte[] uGanss = new BigInteger("777701019898", 16).toByteArray();
            UtranGANSSpositioningData utranGANSSpositioningData = new UtranGANSSpositioningDataImpl(uGanss);
            ServingNodeAddress servingNodeAddress = mapFactory.createServingNodeAddressMscNumber(mscNumber);

            mapDialogLsm.addProvideSubscriberLocationResponse(invokeId, extGeographicalInformation, positioningDataInformation, utranPositioningDataInfo,
                ageOfLocationEstimate, additionalLocationEstimate, mapExtensionContainer, deferredMTLRResponseIndicator, cellGlobalIdOrServiceAreaIdOrLAI,
                saiPresent, accuracyFulfilmentIndicator, velocityEstimate, moLrShortCircuitIndicator, geranGANSSpositioningData, utranGANSSpositioningData,
                servingNodeAddress);
            // This will initiate the TC-BEGIN with INVOKE component
            mapDialogLsm.close(false);

        } catch (MAPException mapException) {
            logger.error("MAP Exception while processing onProvideSubscriberLocationRequest ", mapException);
        } catch (Exception e) {
            logger.error("Exception while processing onProvideSubscriberLocationRequest ", e);
        }

    }

    @Override
    public void onProvideSubscriberLocationResponse(ProvideSubscriberLocationResponse provideSubscriberLocationResponse) {

        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onProvideSubscriberLocationResponse  for DialogId=%d",
                provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
        } else {
            logger.info(String.format("onProvideSubscriberLocationResponse  for DialogId=%d",
                provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
        }

        try {

            if (provideSubscriberLocationResponse.getLocationEstimate() != null) {
                ExtGeographicalInformation locationEstimate = provideSubscriberLocationResponse.getLocationEstimate();
                Double latitude = locationEstimate.getLatitude();
                Double longitude = locationEstimate.getLongitude();
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format("Rx onProvideSubscriberLocationResponse LocationEstimate, latitude = %d " + latitude + ", longitude: " +
                        longitude + "for DialogId=%d", provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));

                } else {
                    logger.info(String.format("Rx onProvideSubscriberLocationResponse LocationEstimate: "
                            + provideSubscriberLocationResponse.getLocationEstimate() + "for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                }
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format(
                        "Rx onProvideSubscriberLocationResponse, Incorrect LocationEstimate received for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                } else {
                    logger.info(String.format(
                        "Rx onProvideSubscriberLocationResponse, Incorrect LocationEstimate received for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                }
            }

            if (provideSubscriberLocationResponse.getGeranPositioningData() != null) {
                PositioningDataInformation geranPositioningData = provideSubscriberLocationResponse.getGeranPositioningData();
                String geranPositioning = geranPositioningData.getData().toString();
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format("Rx onProvideSubscriberLocationResponse GeranPositioningData = %s " + geranPositioning +
                        "for DialogId=%d", provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));

                } else {
                    logger.info(String.format("Rx onProvideSubscriberLocationResponse GeranPositioningData: "
                            + provideSubscriberLocationResponse.getGeranPositioningData() + ", for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                }
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format(
                        "Rx onProvideSubscriberLocationResponse, Incorrect GeranPositioningData received for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                } else {
                    logger.info(String.format(
                        "Rx onProvideSubscriberLocationResponse, Incorrect GeranPositioningData received for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                }
            }

            if (provideSubscriberLocationResponse.getUtranPositioningData() != null) {
                UtranPositioningDataInfo utranPositioningData = provideSubscriberLocationResponse.getUtranPositioningData();
                String utranPositioning = utranPositioningData.getData().toString();
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format("Rx onProvideSubscriberLocationResponse UtranPositioningData = %s " + utranPositioning +
                        "for DialogId=%d", provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));

                } else {
                    logger.info(String.format("Rx onProvideSubscriberLocationResponse UtranPositioningData: "
                            + provideSubscriberLocationResponse.getUtranPositioningData() + ", for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                }
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format(
                        "Rx onProvideSubscriberLocationResponse, Incorrect UtranPositioningData received for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                } else {
                    logger.info(String.format(
                        "Rx onProvideSubscriberLocationResponse, Incorrect UtranPositioningData received for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                }
            }

            if (provideSubscriberLocationResponse.getAgeOfLocationEstimate() != null) {
                Integer ageOfLocationEstimate = provideSubscriberLocationResponse.getAgeOfLocationEstimate();
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format("Rx onProvideSubscriberLocationResponse AgeOfLocationEstimate = %d " + ageOfLocationEstimate +
                        "for DialogId=%d", provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));

                } else {
                    logger.info(String.format("Rx onProvideSubscriberLocationResponse AgeOfLocationEstimate: "
                            + provideSubscriberLocationResponse.getAgeOfLocationEstimate() + ", for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                }
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format(
                        "Rx onProvideSubscriberLocationResponse, Incorrect AgeOfLocationEstimate received for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                } else {
                    logger.info(String.format(
                        "Rx onProvideSubscriberLocationResponse, Incorrect AgeOfLocationEstimate received for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                }
            }

            if (provideSubscriberLocationResponse.getAdditionalLocationEstimate() != null) {
                AddGeographicalInformation additionalLocationEstimate = provideSubscriberLocationResponse.getAdditionalLocationEstimate();
                Double additionalLatitude = additionalLocationEstimate.getLatitude();
                Double additionalLongitude = additionalLocationEstimate.getLongitude();
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format("Rx onProvideSubscriberLocationResponse AdditionalLocationEstimate, latitude = %d "
                            + additionalLatitude + ", longitude: " +
                            additionalLongitude + "for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));

                } else {
                    logger.info(String.format("Rx onProvideSubscriberLocationResponse AdditionalLocationEstimate: "
                            + provideSubscriberLocationResponse.getAdditionalLocationEstimate() + "for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                }
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format(
                        "Rx onProvideSubscriberLocationResponse, Incorrect AdditionalLocationEstimate received for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                } else {
                    logger.info(String.format(
                        "Rx onProvideSubscriberLocationResponse, Incorrect AdditionalLocationEstimate received for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                }
            }

            if (provideSubscriberLocationResponse.getExtensionContainer() != null) {
                MAPExtensionContainer mapExtensionContainer = provideSubscriberLocationResponse.getExtensionContainer();
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format("Rx onProvideSubscriberLocationResponse MAPExtensionContainer not null" +
                        "for DialogId=%d", provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));

                } else {
                    logger.info(String.format("Rx onProvideSubscriberLocationResponse MAPExtensionContainer: "
                            + mapExtensionContainer + ", for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                }
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format(
                        "Rx onProvideSubscriberLocationResponse, NULL MAPExtensionContainer received for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                } else {
                    logger.info(String.format(
                        "Rx onProvideSubscriberLocationResponse, NULL MAPExtensionContainer received for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                }
            }

            if (provideSubscriberLocationResponse.getDeferredMTLRResponseIndicator() == false ||
                provideSubscriberLocationResponse.getDeferredMTLRResponseIndicator() == true) {
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format("Rx onProvideSubscriberLocationResponse DeferredMTLRResponseIndicator: "
                            + provideSubscriberLocationResponse.getDeferredMTLRResponseIndicator() + ", for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));

                } else {
                    logger.info(String.format("Rx onProvideSubscriberLocationResponse DeferredMTLRResponseIndicator: "
                            + provideSubscriberLocationResponse.getDeferredMTLRResponseIndicator() + ", for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                }
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format(
                        "Rx onProvideSubscriberLocationResponse, INCORRECT DeferredMTLRResponseIndicator = "
                            + provideSubscriberLocationResponse.getDeferredMTLRResponseIndicator() + " " +
                            "received for DialogId=%d", provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                } else {
                    logger.info(String.format("Rx onProvideSubscriberLocationResponse, INCORRECT DeferredMTLRResponseIndicator = "
                        + provideSubscriberLocationResponse.getDeferredMTLRResponseIndicator() + " " +
                        "received for DialogId=%d", provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                }
            }

            if (provideSubscriberLocationResponse.getCellIdOrSai() != null) {
                CellGlobalIdOrServiceAreaIdOrLAI cellIdOrSai = provideSubscriberLocationResponse.getCellIdOrSai();
                String cidOrSai = cellIdOrSai.getCellGlobalIdOrServiceAreaIdFixedLength().toString();
                String laiFixedLength = cellIdOrSai.getLAIFixedLength().toString();
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format("Rx onProvideSubscriberLocationResponse CellIdOrSai, CellGlobalIdOrServiceAreaIdOrLAI = %s " + cidOrSai +
                        ", LAIFixedLength: " + laiFixedLength +
                        ", for DialogId=%d", provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));

                } else {
                    logger.info(String.format("Rx onProvideSubscriberLocationResponse CellIdOrSai: "
                            + provideSubscriberLocationResponse.getCellIdOrSai() + "for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                }
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format(
                        "Rx onProvideSubscriberLocationResponse, Incorrect CellIdOrSai received for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                } else {
                    logger.info(String.format(
                        "Rx onProvideSubscriberLocationResponse, Incorrect CellIdOrSai received for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                }
            }

            if (provideSubscriberLocationResponse.getSaiPresent() == false ||
                provideSubscriberLocationResponse.getSaiPresent() == true) {
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format("Rx onProvideSubscriberLocationResponse SaiPresent: "
                            + provideSubscriberLocationResponse.getSaiPresent() + ", for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));

                } else {
                    if (logger.isDebugEnabled()) {
                        logger.debug(String.format(
                            "Rx onProvideSubscriberLocationResponse, Incorrect SaiPresent received for DialogId=%d",
                            provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                    } else {
                        logger.info(String.format(
                            "Rx onProvideSubscriberLocationResponse, Incorrect SaiPresent received for DialogId=%d",
                            provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                    }
                }
            }

            if (provideSubscriberLocationResponse.getAccuracyFulfilmentIndicator() != null) {
                AccuracyFulfilmentIndicator accuracyFulfilmentIndicator = provideSubscriberLocationResponse.getAccuracyFulfilmentIndicator();
                int indicator = accuracyFulfilmentIndicator.getIndicator();
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format("Rx onProvideSubscriberLocationResponse AccuracyFulfilmentIndicator, indicator = %d " + indicator +
                        ", for DialogId=%d", provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));

                } else {
                    logger.info(String.format("Rx onProvideSubscriberLocationResponse AccuracyFulfilmentIndicator: "
                            + provideSubscriberLocationResponse.getAccuracyFulfilmentIndicator() + "for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                }
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format(
                        "Rx onProvideSubscriberLocationResponse, Incorrect AccuracyFulfilmentIndicator received for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                } else {
                    logger.info(String.format(
                        "Rx onProvideSubscriberLocationResponse, Incorrect AccuracyFulfilmentIndicator received for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                }
            }

            if (provideSubscriberLocationResponse.getVelocityEstimate() != null) {
                VelocityEstimate velocityEstimate = provideSubscriberLocationResponse.getVelocityEstimate();
                long horizontalSpeed = velocityEstimate.getHorizontalSpeed();
                long verticalSpeed = velocityEstimate.getVerticalSpeed();
                int velocityType = velocityEstimate.getVelocityType().getCode();
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format("Rx onProvideSubscriberLocationResponse VelocityEstimate, horizontal speed = %d " + horizontalSpeed +
                        ", vertical speed: " + verticalSpeed + "velocity type: " + velocityType
                        + ", for DialogId=%d", provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                } else {
                    logger.info(String.format("Rx onProvideSubscriberLocationResponse VelocityEstimate: "
                            + provideSubscriberLocationResponse.getVelocityEstimate() + "for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                }
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format(
                        "Rx onProvideSubscriberLocationResponse, Incorrect VelocityEstimate received for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                } else {
                    logger.info(String.format(
                        "Rx onProvideSubscriberLocationResponse, Incorrect VelocityEstimate received for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                }
            }

            if (provideSubscriberLocationResponse.getMoLrShortCircuitIndicator() == false ||
                provideSubscriberLocationResponse.getMoLrShortCircuitIndicator() == true) {
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format("Rx onProvideSubscriberLocationResponse SaiPresent: "
                            + provideSubscriberLocationResponse.getMoLrShortCircuitIndicator() + ", for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));

                } else {
                    logger.info(String.format("Rx onProvideSubscriberLocationResponse SaiPresent: "
                            + provideSubscriberLocationResponse.getMoLrShortCircuitIndicator() + ", for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));

                }
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format(
                        "Rx onProvideSubscriberLocationResponse, Incorrect MoLrShortCircuitIndicator received for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                } else {
                    logger.info(String.format(
                        "Rx onProvideSubscriberLocationResponse, Incorrect MoLrShortCircuitIndicator received for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                }
            }

            if (provideSubscriberLocationResponse.getGeranGANSSpositioningData() != null) {
                GeranGANSSpositioningData geranGANSSpositioningDataPositioningData = provideSubscriberLocationResponse.getGeranGANSSpositioningData();
                String geranGanssPositioning = geranGANSSpositioningDataPositioningData.getData().toString();
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format("Rx onProvideSubscriberLocationResponse GeranGANSSPositioningData = %s " + geranGanssPositioning +
                        "for DialogId=%d", provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));

                } else {
                    logger.info(String.format("Rx onProvideSubscriberLocationResponse GeranGANSSPositioningData: "
                            + provideSubscriberLocationResponse.getGeranGANSSpositioningData() + ", for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                }
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format(
                        "Rx onProvideSubscriberLocationResponse, Incorrect GeranGANSSPositioningData received for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                } else {
                    logger.info(String.format(
                        "Rx onProvideSubscriberLocationResponse, Incorrect GeranGANSSPositioningData received for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                }
            }

            if (provideSubscriberLocationResponse.getUtranGANSSpositioningData() != null) {
                UtranGANSSpositioningData utranGANSSpositioningDataPositioningData = provideSubscriberLocationResponse.getUtranGANSSpositioningData();
                String utranGanssPositioning = utranGANSSpositioningDataPositioningData.getData().toString();
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format("Rx onProvideSubscriberLocationResponse UtranGANSSpositioningData = %s " + utranGanssPositioning +
                        "for DialogId=%d", provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));

                } else {
                    logger.info(String.format("Rx onProvideSubscriberLocationResponse UtranGANSSpositioningData: "
                            + provideSubscriberLocationResponse.getUtranGANSSpositioningData() + ", for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                }
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format(
                        "Rx onProvideSubscriberLocationResponse, Incorrect UtranGANSSpositioningData received for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                } else {
                    logger.info(String.format(
                        "Rx onProvideSubscriberLocationResponse, Incorrect UtranGANSSpositioningData received for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                }
            }

            if (provideSubscriberLocationResponse.getTargetServingNodeForHandover() != null) {
                ServingNodeAddress servingNodeAddress = provideSubscriberLocationResponse.getTargetServingNodeForHandover();
                String mscNumber = servingNodeAddress.getMscNumber().toString();
                String sgsnNumber = servingNodeAddress.getSgsnNumber().toString();
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format("Rx onProvideSubscriberLocationResponse ServingNode, MSC Number = %s " + mscNumber +
                        ", SGSN Number = %s " + sgsnNumber +
                        ", for DialogId=%d", provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));

                } else {
                    logger.info(String.format("Rx onProvideSubscriberLocationResponse ServingNode, MSC Number = %s " + mscNumber +
                        ", SGSN Number = %s " + sgsnNumber +
                        ", for DialogId=%d", provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                }
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format(
                        "Rx onProvideSubscriberLocationResponse, Incorrect ServingNode received for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                } else {
                    logger.info(String.format(
                        "Rx onProvideSubscriberLocationResponse, Incorrect ServingNode received for DialogId=%d",
                        provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId()));
                }
            }

        } catch (Exception e) {
            logger.info(String.format("onProvideSubscriberLocationResponse for Dialog=%d",
                provideSubscriberLocationResponse.getMAPDialog().getLocalDialogId(), ", thrown: " + e.getStackTrace()));
        }
    }

    @Override
    public void onSubscriberLocationReportRequest(SubscriberLocationReportRequest subscriberLocationReportRequest) {

        if (logger.isDebugEnabled()) {
            logger.debug(
                String.format("onSubscriberLocationReportRequest for DialogId=%d", subscriberLocationReportRequest.getMAPDialog().getLocalDialogId()));
        }
        if (logger.isInfoEnabled()) {
            logger.info(String.format("onSubscriberLocationReportRequest for DialogId=%d", subscriberLocationReportRequest.getMAPDialog().getLocalDialogId()));
        }

        try {
            long invokeId = subscriberLocationReportRequest.getInvokeId();
            MAPDialogLsm mapDialogLsm = subscriberLocationReportRequest.getMAPDialog();
            mapDialogLsm.setUserObject(invokeId);

            // Create Routing Information parameters for concerning MAP operation
            MAPParameterFactoryImpl mapFactory = new MAPParameterFactoryImpl();
            ISDNAddressString naEsrd = new ISDNAddressStringImpl(AddressNature.international_number,
                NumberingPlan.ISDN, "5982123007");
            ISDNAddressString naEsrk = new ISDNAddressStringImpl(AddressNature.international_number,
                NumberingPlan.ISDN, "5982123009");
/*
            long[] oid = {0, 0, 17, 773, 1, 1, 1};
            String pExtData = "1144";
            byte[] privateExtData = pExtData.getBytes();
            MAPPrivateExtension mapPrivateExtension = new MAPPrivateExtensionImpl(oid, privateExtData);
            ArrayList<MAPPrivateExtension> mapPrivateExtensions = new ArrayList<MAPPrivateExtension>();
            mapPrivateExtensions.add(mapPrivateExtension);
            String pcsExts = "1033";
            byte[] pcsExtensions = pcsExts.getBytes();
            MAPExtensionContainer mapExtensionContainer = new MAPExtensionContainerImpl(mapPrivateExtensions, pcsExtensions);
*/
            MAPExtensionContainer mapExtensionContainer = null;

            mapDialogLsm.addSubscriberLocationReportResponse(invokeId, naEsrd, naEsrk, mapExtensionContainer);

            // This will initiate the TC-BEGIN with INVOKE component
            mapDialogLsm.close(false);

        } catch (MAPException mapException) {
            logger.error("MAP Exception while processing onSubscriberLocationReportRequest ", mapException);
        } catch (Exception e) {
            logger.error("Exception while processing onSubscriberLocationReportRequest ", e);
        }

    }

    @Override
    public void onSubscriberLocationReportResponse(SubscriberLocationReportResponse subscriberLocationReportResponse) {

        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onSubscriberLocationReportResponse  for DialogId=%d",
                subscriberLocationReportResponse.getMAPDialog().getLocalDialogId()));
        } else {
            logger.info(String.format("onSubscriberLocationReportResponse  for DialogId=%d",
                subscriberLocationReportResponse.getMAPDialog().getLocalDialogId()));
        }

        try {

            if (subscriberLocationReportResponse.getNaESRD() != null) {
                ISDNAddressString naEsrd = subscriberLocationReportResponse.getNaESRD();
                String naESRDaddress = naEsrd.getAddress();
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format("Rx onSubscriberLocationReportResponse NaESRD = %s " + naESRDaddress +
                        "for DialogId=%d", subscriberLocationReportResponse.getMAPDialog().getLocalDialogId()));

                } else {
                    logger.info(String.format("Rx onSubscriberLocationReportResponse NaESRD: "
                            + subscriberLocationReportResponse.getNaESRD() + ", for DialogId=%d",
                        subscriberLocationReportResponse.getMAPDialog().getLocalDialogId()));
                }
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format(
                        "Rx onSubscriberLocationReportResponse, Incorrect NaESRD received for DialogId=%d",
                        subscriberLocationReportResponse.getMAPDialog().getLocalDialogId()));
                } else {
                    logger.info(String.format(
                        "Rx onSubscriberLocationReportResponse, Incorrect NaESRD received for DialogId=%d",
                        subscriberLocationReportResponse.getMAPDialog().getLocalDialogId()));
                }
            }

            if (subscriberLocationReportResponse.getNaESRK() != null) {
                ISDNAddressString naEsrk = subscriberLocationReportResponse.getNaESRD();
                String naESRKaddress = naEsrk.getAddress();
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format("Rx onSubscriberLocationReportResponse NaESRK = %s " + naESRKaddress +
                        "for DialogId=%d", subscriberLocationReportResponse.getMAPDialog().getLocalDialogId()));

                } else {
                    logger.info(String.format("Rx onSubscriberLocationReportResponse NaESRK: "
                            + subscriberLocationReportResponse.getNaESRK() + ", for DialogId=%d",
                        subscriberLocationReportResponse.getMAPDialog().getLocalDialogId()));
                }
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format(
                        "Rx onSubscriberLocationReportResponse, Incorrect NaESRK received for DialogId=%d",
                        subscriberLocationReportResponse.getMAPDialog().getLocalDialogId()));
                } else {
                    logger.info(String.format(
                        "Rx onSubscriberLocationReportResponse, Incorrect NaESRK received for DialogId=%d",
                        subscriberLocationReportResponse.getMAPDialog().getLocalDialogId()));
                }
            }

            if (subscriberLocationReportResponse.getExtensionContainer() != null) {
                MAPExtensionContainer extContainer = subscriberLocationReportResponse.getExtensionContainer();
                String mapExtensionContainer = extContainer.toString();
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format("Rx onSubscriberLocationReportResponse MAPExtensionContainer = %s " + mapExtensionContainer +
                        "for DialogId=%d", subscriberLocationReportResponse.getMAPDialog().getLocalDialogId()));

                } else {
                    logger.info(String.format("Rx onSubscriberLocationReportResponse MAPExtensionContainer: "
                            + subscriberLocationReportResponse.getExtensionContainer() + ", for DialogId=%d",
                        subscriberLocationReportResponse.getMAPDialog().getLocalDialogId()));
                }
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format(
                        "Rx onSubscriberLocationReportResponse, Incorrect MAPExtensionContainer received for DialogId=%d",
                        subscriberLocationReportResponse.getMAPDialog().getLocalDialogId()));
                } else {
                    logger.info(String.format(
                        "Rx onSubscriberLocationReportResponse, Incorrect MAPExtensionContainer received for DialogId=%d",
                        subscriberLocationReportResponse.getMAPDialog().getLocalDialogId()));
                }
            }

        } catch (Exception e) {
            logger.error(String.format("Error while processing onSubscriberLocationReportResponse for Dialog=%d",
                subscriberLocationReportResponse.getMAPDialog().getLocalDialogId()));
        }

    }

    @Override
    public void onUpdateGprsLocationRequest(UpdateGprsLocationRequest updateGprsLocationRequest) {

        if (logger.isDebugEnabled()) {
            logger.debug(
                String.format("onUpdateGprsLocationRequest for DialogId=%d", updateGprsLocationRequest.getMAPDialog().getLocalDialogId()));
        }
        if (logger.isInfoEnabled()) {
            logger.info(String.format("onUpdateGprsLocationRequest for DialogId=%d", updateGprsLocationRequest.getMAPDialog().getLocalDialogId()));
        }

        try {
            MAPDialogMobility mapDialogMobility = updateGprsLocationRequest.getMAPDialog();
            long invokeId = updateGprsLocationRequest.getInvokeId();
            mapDialogMobility.setUserObject(invokeId);
            MAPProvider mapProvider = this.clientMapProvider;

            MAPParameterFactoryImpl mapFactory = new MAPParameterFactoryImpl();

            ISDNAddressString hlrNumber = new ISDNAddressStringImpl(AddressNature.international_number,
                NumberingPlan.ISDN, "5982123000");
            MAPExtensionContainer extensionContainer = null;
            boolean addCapability = true;
            boolean sgsnMmeSeparationSupported = true;

            mapDialogMobility.addUpdateGprsLocationResponse(invokeId, hlrNumber, extensionContainer, addCapability, sgsnMmeSeparationSupported);

            // This will initiate the TC-BEGIN with INVOKE component
            mapDialogMobility.close(false);

        } catch (MAPException mapException) {
            logger.error("MAP Exception while processing AnyTimeInterrogationRequest ", mapException);
        } catch (Exception e) {
            logger.error("Exception while processing AnyTimeInterrogationRequest ", e);
        }
    }

    @Override
    public void onUpdateGprsLocationResponse(UpdateGprsLocationResponse updateGprsLocationResponse) {

        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onUpdateGprsLocationResponse  for DialogId=%d",
                updateGprsLocationResponse.getMAPDialog().getLocalDialogId()));
        } else {
            logger.info(String.format("onUpdateGprsLocationResponse  for DialogId=%d",
                updateGprsLocationResponse.getMAPDialog().getLocalDialogId()));
        }

        try {

            if (updateGprsLocationResponse.getHlrNumber() != null) {
                ISDNAddressString hlrNumber = updateGprsLocationResponse.getHlrNumber();
                String hlrNum = hlrNumber.toString();
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format("Rx onUpdateGprsLocationResponse HLR Number = %s " + hlrNum +
                        "for DialogId=%d", updateGprsLocationResponse.getMAPDialog().getLocalDialogId()));

                } else {
                    logger.info(String.format("Rx onUpdateGprsLocationResponse HLR Number: "
                            + hlrNum + ", for DialogId=%d",
                        updateGprsLocationResponse.getMAPDialog().getLocalDialogId()));
                }
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format(
                        "Rx onUpdateGprsLocationResponse, Incorrect HLR Number received for DialogId=%d",
                        updateGprsLocationResponse.getMAPDialog().getLocalDialogId()));
                } else {
                    logger.info(String.format(
                        "Rx onUpdateGprsLocationResponse, Incorrect HLR Number received for DialogId=%d",
                        updateGprsLocationResponse.getMAPDialog().getLocalDialogId()));
                }
            }

            boolean addCapability = updateGprsLocationResponse.getAddCapability();
            if (logger.isDebugEnabled()) {
                logger.debug(String.format("Rx onUpdateGprsLocationResponse additional Capability = %s " + addCapability +
                    "for DialogId=%d", updateGprsLocationResponse.getMAPDialog().getLocalDialogId()));
            } else {
                logger.info(String.format("Rx onUpdateGprsLocationResponse additional Capability: "
                        + addCapability + ", for DialogId=%d",
                    updateGprsLocationResponse.getMAPDialog().getLocalDialogId()));
            }

            boolean sgsnMmeSeparationSupported = updateGprsLocationResponse.getSgsnMmeSeparationSupported();
            if (logger.isDebugEnabled()) {
                logger.debug(String.format("Rx onUpdateGprsLocationResponse SGSN/MEE Separation Supported = %s " + sgsnMmeSeparationSupported +
                    "for DialogId=%d", updateGprsLocationResponse.getMAPDialog().getLocalDialogId()));
            } else {
                logger.info(String.format("Rx onUpdateGprsLocationResponse SGSN/MEE Separation Supported: "
                        + sgsnMmeSeparationSupported + ", for DialogId=%d",
                    updateGprsLocationResponse.getMAPDialog().getLocalDialogId()));
            }

            if (updateGprsLocationResponse.getExtensionContainer() != null) {
                MAPExtensionContainer extContainer = updateGprsLocationResponse.getExtensionContainer();
                String mapExtensionContainer = extContainer.toString();
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format("Rx onUpdateGprsLocationResponse MAPExtensionContainer = %s " + mapExtensionContainer +
                        "for DialogId=%d", updateGprsLocationResponse.getMAPDialog().getLocalDialogId()));

                } else {
                    logger.info(String.format("Rx onUpdateGprsLocationResponse MAPExtensionContainer: "
                            + updateGprsLocationResponse.getExtensionContainer() + ", for DialogId=%d",
                        updateGprsLocationResponse.getMAPDialog().getLocalDialogId()));
                }
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug(String.format(
                        "Rx onUpdateGprsLocationResponse, Incorrect MAPExtensionContainer received for DialogId=%d",
                        updateGprsLocationResponse.getMAPDialog().getLocalDialogId()));
                } else {
                    logger.info(String.format(
                        "Rx onUpdateGprsLocationResponse, Incorrect MAPExtensionContainer received for DialogId=%d",
                        updateGprsLocationResponse.getMAPDialog().getLocalDialogId()));
                }
            }

            /*
ISDNAddressString getHlrNumber();

    MAPExtensionContainer getExtensionContainer();

    boolean getAddCapability();

    boolean getSgsnMmeSeparationSupported();
 */

        } catch (Exception e) {
            logger.error(String.format("Error while processing onUpdateGprsLocationResponse for Dialog=%d",
                updateGprsLocationResponse.getMAPDialog().getLocalDialogId()));
        }

    }


    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.MAPDialogListener#onDialogDelimiter
     * (org.restcomm.protocols.ss7.map.api.MAPDialog)
     */
    @Override
    public void onDialogDelimiter(MAPDialog mapDialog) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onDialogDelimiter for DialogId=%d", mapDialog.getLocalDialogId()));
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.MAPDialogListener#onDialogRequest
     * (org.restcomm.protocols.ss7.map.api.MAPDialog, org.restcomm.protocols.ss7.map.api.primitives.AddressString,
     * org.restcomm.protocols.ss7.map.api.primitives.AddressString,
     * org.restcomm.protocols.ss7.map.api.primitives.MAPExtensionContainer)
     */
    @Override
    public void onDialogRequest(MAPDialog mapDialog, AddressString destReference, AddressString origReference,
                                MAPExtensionContainer extensionContainer) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format(
                "onDialogRequest for DialogId=%d DestinationReference=%s OriginReference=%s MAPExtensionContainer=%s",
                mapDialog.getLocalDialogId(), destReference, origReference, extensionContainer));
        }
    }

    @Override
    public void onDialogRequestEricsson(MAPDialog mapDialog, AddressString destReference, AddressString origReference, AddressString eriMsisdn, AddressString eriVlrNo) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onDialogRequest for DialogId=%d DestinationReference=%s OriginReference=%s ",
                mapDialog.getLocalDialogId(), destReference, origReference));
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.MAPDialogListener#onDialogAccept( org.restcomm.protocols.ss7.map.api.MAPDialog,
     * org.restcomm.protocols.ss7.map.api.primitives.MAPExtensionContainer)
     */
    @Override
    public void onDialogAccept(MAPDialog mapDialog, MAPExtensionContainer extensionContainer) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onDialogAccept for DialogId=%d MAPExtensionContainer=%s", mapDialog.getLocalDialogId(),
                extensionContainer));
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.MAPDialogListener#onDialogReject( org.restcomm.protocols.ss7.map.api.MAPDialog,
     * org.restcomm.protocols.ss7.map.api.dialog.MAPRefuseReason, org.restcomm.protocols.ss7.map.api.dialog.MAPProviderError,
     * org.restcomm.protocols.ss7.tcap.asn.ApplicationContextName,
     * org.restcomm.protocols.ss7.map.api.primitives.MAPExtensionContainer)
     */
    @Override
    public void onDialogReject(MAPDialog mapDialog, MAPRefuseReason refuseReason,
                               ApplicationContextName alternativeApplicationContext, MAPExtensionContainer extensionContainer) {
        logger.error(String.format(
            "onDialogReject for DialogId=%d MAPRefuseReason=%s ApplicationContextName=%s MAPExtensionContainer=%s",
            mapDialog.getLocalDialogId(), refuseReason, alternativeApplicationContext, extensionContainer));
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.MAPDialogListener#onDialogUserAbort
     * (org.restcomm.protocols.ss7.map.api.MAPDialog, org.restcomm.protocols.ss7.map.api.dialog.MAPUserAbortChoice,
     * org.restcomm.protocols.ss7.map.api.primitives.MAPExtensionContainer)
     */
    @Override
    public void onDialogUserAbort(MAPDialog mapDialog, MAPUserAbortChoice userReason,
                                  MAPExtensionContainer extensionContainer) {
        logger.error(String.format("onDialogUserAbort for DialogId=%d MAPUserAbortChoice=%s MAPExtensionContainer=%s",
            mapDialog.getLocalDialogId(), userReason, extensionContainer));
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.MAPDialogListener#onDialogProviderAbort(org.restcomm.protocols.ss7.map.api.MAPDialog,
     * org.restcomm.protocols.ss7.map.api.dialog.MAPAbortProviderReason,
     * org.restcomm.protocols.ss7.map.api.dialog.MAPAbortSource,
     * org.restcomm.protocols.ss7.map.api.primitives.MAPExtensionContainer)
     */
    @Override
    public void onDialogProviderAbort(MAPDialog mapDialog, MAPAbortProviderReason abortProviderReason,
                                      MAPAbortSource abortSource, MAPExtensionContainer extensionContainer) {
        logger.error(String.format(
            "onDialogProviderAbort for DialogId=%d MAPAbortProviderReason=%s MAPAbortSource=%s MAPExtensionContainer=%s",
            mapDialog.getLocalDialogId(), abortProviderReason, abortSource, extensionContainer));
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.MAPDialogListener#onDialogClose(org .mobicents.protocols.ss7.map.api.MAPDialog)
     */
    @Override
    public void onDialogClose(MAPDialog mapDialog) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("DialogClose for Dialog=%d", mapDialog.getLocalDialogId()));
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.MAPDialogListener#onDialogNotice( org.restcomm.protocols.ss7.map.api.MAPDialog,
     * org.restcomm.protocols.ss7.map.api.dialog.MAPNoticeProblemDiagnostic)
     */
    @Override
    public void onDialogNotice(MAPDialog mapDialog, MAPNoticeProblemDiagnostic noticeProblemDiagnostic) {
        logger.error(String.format("onDialogNotice for DialogId=%d MAPNoticeProblemDiagnostic=%s ",
            mapDialog.getLocalDialogId(), noticeProblemDiagnostic));
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.MAPDialogListener#onDialogResease(org.restcomm.protocols.ss7.map.api.MAPDialog)
     *
     */
    @Override
    public void onDialogRelease(MAPDialog mapDialog) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onDialogResease for DialogId=%d", mapDialog.getLocalDialogId()));
        }

        this.serverEndCount++;

        if (((this.serverEndCount % 10000) == 0) && serverEndCount > 1) {
            long currentTime = System.currentTimeMillis();
            long processingTime = currentTime - serverStart;
            serverStart = currentTime;
            logger.warn("Completed 10000 Dialogs in=" + processingTime + " ms. Dialogs per sec: " + +(float) (10000000 / processingTime));
        }

    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.MAPDialogListener#onDialogTimeout(org.restcomm.protocols.ss7.map.api.MAPDialog)
     *
     */
    @Override
    public void onDialogTimeout(MAPDialog mapDialog) {
        logger.error(String.format("onDialogTimeout for DialogId=%d", mapDialog.getLocalDialogId()));
    }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.MAPServiceListener#onErrorComponent(org.restcomm.protocols.ss7.map.api.MAPDialog,
     * java.lang.Long,org.restcomm.protocols.ss7.map.api.errors.MAPErrorMessage)
     *
     */
    // @Override
    // public void onErrorComponent(MAPDialog mapDialog, Long invokeId, MAPErrorMessage mapErrorMessage) {
    // logger.error(String.format("onErrorComponent for Dialog=%d and invokeId=%d MAPErrorMessage=%s",
    // mapDialog.getLocalDialogId(), invokeId, mapErrorMessage));
    // }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.MAPServiceListener#onRejectComponent
     * (org.restcomm.protocols.ss7.map.api.MAPDialog, java.lang.Long, org.restcomm.protocols.ss7.tcap.asn.comp.Problem)
     */
    // @Override
    // public void onRejectComponent(MAPDialog mapDialog, Long invokeId, Problem problem, boolean isLocalOriginated) {
    // logger.error(String.format("onRejectComponent for Dialog=%d and invokeId=%d Problem=%s isLocalOriginated=%s",
    // mapDialog.getLocalDialogId(), invokeId, problem, isLocalOriginated));
    // }

    /*
     * (non-Javadoc)
     *
     * @see org.restcomm.protocols.ss7.map.api.MAPServiceListener#onInvokeTimeout(org.restcomm.protocols.ss7.map.api.MAPDialog,
     * java.lang.Long)
     */
    // @Override
    // public void onInvokeTimeout(MAPDialog mapDialog, Long invokeId) {
    // logger.error(String.format("onInvokeTimeout for Dialog=%d and invokeId=%d", mapDialog.getLocalDialogId(), invokeId));
    // }

    public void onInsertSubscriberDataRequest(InsertSubscriberDataRequest insertSubscriberData) {

    }

    public void onDeleteSubscriberDataRequest(DeleteSubscriberDataRequest deleteSubsData) {

    }

    public void onErrorComponent(MAPDialog arg0, Long arg1, MAPErrorMessage arg2) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onInsertSubscriberDataResponse(InsertSubscriberDataResponse arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onProvideSubscriberInfoRequest(ProvideSubscriberInfoRequest arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onProvideSubscriberInfoResponse(ProvideSubscriberInfoResponse arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onPurgeMSRequest(PurgeMSRequest arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onPurgeMSResponse(PurgeMSResponse arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onResetRequest(ResetRequest arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onRestoreDataRequest(RestoreDataRequest arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onRestoreDataResponse(RestoreDataResponse arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onSendAuthenticationInfoRequest(SendAuthenticationInfoRequest arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onSendAuthenticationInfoResponse(SendAuthenticationInfoResponse arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onSendIdentificationRequest(SendIdentificationRequest arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onSendIdentificationResponse(SendIdentificationResponse arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onUpdateLocationRequest(UpdateLocationRequest arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onUpdateLocationResponse(UpdateLocationResponse arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onActivateTraceModeRequest_Mobility(ActivateTraceModeRequest_Mobility arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onActivateTraceModeResponse_Mobility(ActivateTraceModeResponse_Mobility arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onAuthenticationFailureReportRequest(AuthenticationFailureReportRequest arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onAuthenticationFailureReportResponse(AuthenticationFailureReportResponse arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onCancelLocationRequest(CancelLocationRequest arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onCancelLocationResponse(CancelLocationResponse arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onCheckImeiRequest(CheckImeiRequest arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onCheckImeiResponse(CheckImeiResponse arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onDeleteSubscriberDataResponse(DeleteSubscriberDataResponse arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onForwardCheckSSIndicationRequest(ForwardCheckSSIndicationRequest arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onInvokeTimeout(MAPDialog arg0, Long arg1) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onMAPMessage(MAPMessage arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onRejectComponent(MAPDialog arg0, Long arg1, Problem arg2, boolean arg3) {
        // TODO Auto-generated method stub

    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

}
