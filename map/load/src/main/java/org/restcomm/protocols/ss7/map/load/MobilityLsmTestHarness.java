package org.restcomm.protocols.ss7.map.load;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.FileAppender;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.apache.log4j.SimpleLayout;
import org.restcomm.protocols.ss7.indicator.RoutingIndicator;
import org.restcomm.protocols.ss7.m3ua.impl.parameter.ParameterFactoryImpl;
import org.restcomm.protocols.ss7.map.api.MAPDialogListener;
import org.restcomm.protocols.ss7.map.api.service.lsm.MAPServiceLsmListener;
import org.restcomm.protocols.ss7.map.api.service.lsm.ProvideSubscriberLocationRequest;
import org.restcomm.protocols.ss7.map.api.service.lsm.ProvideSubscriberLocationResponse;
import org.restcomm.protocols.ss7.map.api.service.lsm.SendRoutingInfoForLCSRequest;
import org.restcomm.protocols.ss7.map.api.service.lsm.SendRoutingInfoForLCSResponse;
import org.restcomm.protocols.ss7.map.api.service.lsm.SubscriberLocationReportRequest;
import org.restcomm.protocols.ss7.map.api.service.lsm.SubscriberLocationReportResponse;
import org.restcomm.protocols.ss7.map.api.service.mobility.MAPServiceMobilityListener;
import org.restcomm.protocols.ss7.map.api.service.mobility.authentication.SendAuthenticationInfoRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.authentication.SendAuthenticationInfoResponse;
import org.restcomm.protocols.ss7.map.api.service.mobility.faultRecovery.ResetRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.faultRecovery.RestoreDataRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.faultRecovery.RestoreDataResponse;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.PurgeMSRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.PurgeMSResponse;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.SendIdentificationRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.SendIdentificationResponse;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.UpdateGprsLocationRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.UpdateGprsLocationResponse;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.UpdateLocationRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.locationManagement.UpdateLocationResponse;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.AnyTimeInterrogationRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.AnyTimeInterrogationResponse;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.ProvideSubscriberInfoRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberInformation.ProvideSubscriberInfoResponse;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.DeleteSubscriberDataRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.InsertSubscriberDataRequest;
import org.restcomm.protocols.ss7.map.api.service.mobility.subscriberManagement.InsertSubscriberDataResponse;
import org.restcomm.protocols.ss7.sccp.impl.parameter.SccpAddressImpl;
import org.restcomm.protocols.ss7.sccp.parameter.SccpAddress;

import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.Properties;

/**
 * @author <a href="mailto:fernando.mendioroz@gmail.com"> Fernando Mendioroz </a>
 */
public abstract class MobilityLsmTestHarness implements MAPDialogListener, MAPServiceMobilityListener, MAPServiceLsmListener {

    private static final Logger logger = Logger.getLogger("map.test");

    protected static final String LOG_FILE_NAME = "log.file.name";
    protected static String logFileName = "maplog.txt";

    protected static int NDIALOGS = 50000;

    protected static int MAXCONCURRENTDIALOGS = 1000;

    // MTPL3 Details
    protected static int CLIENT_SPC = 1; // Client Signaling Point Code
    protected static int SERVER_SPC = 2; // Server Signaling Point Code
    protected static int NETWORK_INDICATOR = 2; // National Network
    protected static int SERVICE_INDICATOR = 3; // upper layer is SCCP
    protected static int CLIENT_SSN = 145; // Client Sub-System Number
    protected static int SERVER_SSN = 6; // Client Sub-System Number

    // M3UA details
    protected static String CLIENT_IP = "127.0.0.1";
    protected static int CLIENT_PORT = 2345;

    protected static String SERVER_IP = "127.0.0.1";
    protected static int SERVER_PORT = 3434;

    protected static int ROUTING_CONTEXT = 100;

    protected static int DELIVERY_TRANSFER_MESSAGE_THREAD_COUNT = Runtime.getRuntime().availableProcessors() * 2;

    protected final String SERVER_ASSOCIATION_NAME = "serverAssociation";
    protected final String CLIENT_ASSOCIATION_NAME = "clientAssociation";

    protected final String SERVER_NAME = "testserver";

    // TCAP Details
    protected static final int MAX_DIALOGS = 500000;

    public SccpAddress SCCP_CLIENT_ADDRESS = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN, null,
        CLIENT_SPC, CLIENT_SSN);
    public SccpAddress SCCP_SERVER_ADDRESS = new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN, null,
        SERVER_SPC, SERVER_SSN);

    protected final org.restcomm.protocols.ss7.m3ua.impl.parameter.ParameterFactoryImpl factory = new ParameterFactoryImpl();

    protected MobilityLsmTestHarness() {
        init();
    }

    public void init() {
        try {
            Properties tckProperties = new Properties();

            InputStream inStreamLog4j = TestHarness.class.getResourceAsStream("/log4j.properties");

            logger.info("Input Stream = " + inStreamLog4j);

            Properties propertiesLog4j = new Properties();
            try {
                propertiesLog4j.load(inStreamLog4j);
                PropertyConfigurator.configure(propertiesLog4j);
            } catch (Exception e) {
                e.printStackTrace();
                BasicConfigurator.configure();
            }

            logger.debug("log4j configured");

            String lf = System.getProperties().getProperty(LOG_FILE_NAME);
            if (lf != null) {
                logFileName = lf;
            }

            // If a print writer is already created, then just use it.
            try {
                logger.addAppender(new FileAppender(new SimpleLayout(), logFileName));
            } catch (FileNotFoundException fnfe) {

            }
        } catch (Exception ex) {
            ex.printStackTrace();
            throw new RuntimeException(ex);
        }

    }

    public abstract void onAnyTimeInterrogationRequest(AnyTimeInterrogationRequest atiReq);

    public abstract void onAnyTimeInterrogationResponse(AnyTimeInterrogationResponse atiResp);

    public abstract void onInsertSubscriberDataRequest(InsertSubscriberDataRequest insertSubsData);

    public abstract void onDeleteSubscriberDataRequest(DeleteSubscriberDataRequest deleteSubsData);

    public abstract void onInsertSubscriberDataResponse(InsertSubscriberDataResponse arg0);

    public abstract void onProvideSubscriberInfoRequest(ProvideSubscriberInfoRequest arg0);

    public abstract void onProvideSubscriberInfoResponse(ProvideSubscriberInfoResponse arg0);

    public abstract void onPurgeMSRequest(PurgeMSRequest arg0);

    public abstract void onPurgeMSResponse(PurgeMSResponse arg0);

    public abstract void onResetRequest(ResetRequest arg0);

    public abstract void onRestoreDataRequest(RestoreDataRequest arg0);

    public abstract void onRestoreDataResponse(RestoreDataResponse arg0);

    public abstract void onSendAuthenticationInfoRequest(SendAuthenticationInfoRequest arg0);

    public abstract void onSendAuthenticationInfoResponse(SendAuthenticationInfoResponse arg0);

    public abstract void onSendIdentificationRequest(SendIdentificationRequest arg0);

    public abstract void onSendIdentificationResponse(SendIdentificationResponse arg0);

    public abstract void onUpdateGprsLocationRequest(UpdateGprsLocationRequest arg0);

    public abstract void onUpdateGprsLocationResponse(UpdateGprsLocationResponse arg0);

    public abstract void onUpdateLocationRequest(UpdateLocationRequest arg0);

    public abstract void onUpdateLocationResponse(UpdateLocationResponse arg0);

    public abstract void onProvideSubscriberLocationRequest(ProvideSubscriberLocationRequest provideSubscriberLocationRequestIndication);;

    public abstract void onProvideSubscriberLocationResponse(ProvideSubscriberLocationResponse provideSubscriberLocationResponseIndication);

    public abstract void onSubscriberLocationReportRequest(SubscriberLocationReportRequest subscriberLocationReportRequestIndication);

    public abstract void onSubscriberLocationReportResponse(SubscriberLocationReportResponse subscriberLocationReportResponseIndication);

    public abstract void onSendRoutingInfoForLCSRequest(SendRoutingInfoForLCSRequest sendRoutingInforForLCSRequestIndication);

    public abstract void onSendRoutingInfoForLCSResponse(SendRoutingInfoForLCSResponse sendRoutingInforForLCSResponseIndication);

}
