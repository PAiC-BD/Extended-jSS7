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

package org.restcomm.protocols.ss7.sccp.impl;

import io.netty.util.concurrent.DefaultThreadFactory;
import javolution.text.TextBuilder;
import javolution.util.FastMap;
import javolution.xml.XMLBinding;
import javolution.xml.XMLObjectReader;
import javolution.xml.XMLObjectWriter;
import javolution.xml.stream.XMLStreamException;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.restcomm.protocols.ss7.indicator.RoutingIndicator;
import org.restcomm.protocols.ss7.mtp.Mtp3;
import org.restcomm.protocols.ss7.mtp.Mtp3EndCongestionPrimitive;
import org.restcomm.protocols.ss7.mtp.Mtp3PausePrimitive;
import org.restcomm.protocols.ss7.mtp.Mtp3ResumePrimitive;
import org.restcomm.protocols.ss7.mtp.Mtp3StatusCause;
import org.restcomm.protocols.ss7.mtp.Mtp3StatusPrimitive;
import org.restcomm.protocols.ss7.mtp.Mtp3TransferPrimitive;
import org.restcomm.protocols.ss7.mtp.Mtp3UserPart;
import org.restcomm.protocols.ss7.mtp.Mtp3UserPartListener;
import org.restcomm.protocols.ss7.sccp.LongMessageRule;
import org.restcomm.protocols.ss7.sccp.LongMessageRuleType;
import org.restcomm.protocols.ss7.sccp.MaxConnectionCountReached;
import org.restcomm.protocols.ss7.sccp.Mtp3ServiceAccessPoint;
import org.restcomm.protocols.ss7.sccp.RemoteSignalingPointCode;
import org.restcomm.protocols.ss7.sccp.Router;
import org.restcomm.protocols.ss7.sccp.SccpCongestionControlAlgo;
import org.restcomm.protocols.ss7.sccp.SccpConnectionState;
import org.restcomm.protocols.ss7.sccp.SccpManagementEventListener;
import org.restcomm.protocols.ss7.sccp.SccpProtocolVersion;
import org.restcomm.protocols.ss7.sccp.SccpProvider;
import org.restcomm.protocols.ss7.sccp.SccpResource;
import org.restcomm.protocols.ss7.sccp.SccpStack;
import org.restcomm.protocols.ss7.sccp.impl.message.MessageFactoryImpl;
import org.restcomm.protocols.ss7.sccp.impl.message.SccpAddressedMessageImpl;
import org.restcomm.protocols.ss7.sccp.impl.message.SccpDataNoticeTemplateMessageImpl;
import org.restcomm.protocols.ss7.sccp.impl.message.SccpMessageImpl;
import org.restcomm.protocols.ss7.sccp.impl.message.SccpSegmentableMessageImpl;
import org.restcomm.protocols.ss7.sccp.impl.parameter.LocalReferenceImpl;
import org.restcomm.protocols.ss7.sccp.impl.parameter.SccpAddressImpl;
import org.restcomm.protocols.ss7.sccp.impl.parameter.SegmentationImpl;
import org.restcomm.protocols.ss7.sccp.impl.router.RouterImpl;
import org.restcomm.protocols.ss7.sccp.message.SccpConnMessage;
import org.restcomm.protocols.ss7.sccp.parameter.GlobalTitle;
import org.restcomm.protocols.ss7.sccp.parameter.LocalReference;
import org.restcomm.protocols.ss7.sccp.parameter.ProtocolClass;
import org.restcomm.protocols.ss7.sccp.parameter.ReturnCauseValue;
import org.restcomm.protocols.ss7.sccp.parameter.SccpAddress;
import org.restcomm.protocols.ss7.scheduler.Scheduler;
import org.restcomm.protocols.ss7.ss7ext.Ss7ExtInterface;
import org.restcomm.protocols.ss7.ss7ext.Ss7ExtSccpInterface;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static org.restcomm.protocols.ss7.sccp.impl.message.MessageUtil.calculateLudtFieldsLengthWithoutData;
import static org.restcomm.protocols.ss7.sccp.impl.message.MessageUtil.calculateUdtFieldsLengthWithoutData;
import static org.restcomm.protocols.ss7.sccp.impl.message.MessageUtil.calculateXudtFieldsLengthWithoutData;
import static org.restcomm.protocols.ss7.sccp.impl.message.MessageUtil.calculateXudtFieldsLengthWithoutData2;

/**
 *
 * @author amit bhayani
 * @author baranowb
 * @author sergey vetyutnev
 *
 */
public class SccpStackImpl implements SccpStack, Mtp3UserPartListener {
    protected final Logger logger;

    protected static final String SCCP_MANAGEMENT_PERSIST_DIR_KEY = "sccpmanagement.persist.dir";
    protected static final String USER_DIR_KEY = "user.dir";
    protected static final String PERSIST_FILE_NAME = "management2.xml";
    private static final String TAB_INDENT = "\t";
    private static final String CLASS_ATTRIBUTE = "type";
    private static final String Z_MARGIN_UDT_MSG = "zmarginxudtmessage";

    private static final String CONN_EST_TIMER_DELAY = "connesttimerdelay";
    private static final String IAS_TIMER_DELAY = "iastimerdelay";
    private static final String IAR_TIMER_DELAY = "iartimerdelay";
    private static final String REL_TIMER_DELAY = "reltimerdelay";
    private static final String REPEAT_REL_TIMER_DELAY = "repeatreltimerdelay";
    private static final String INT_TIMER_DELAY = "inttimerdelay";
    private static final String GUARD_TIMER_DELAY = "guardtimerdelay";
    private static final String RESET_TIMER_DELAY = "resettimerdelay";
    private static final String REASSEMBLY_TIMER_DELAY = "reassemblytimerdelay";

    private static final String MAX_DATA_MSG = "maxdatamessage";
    private static final String PERIOD_OF_LOG = "periodoflogging";
    private static final String REMOVE_SPC = "removespc";
    private static final String RESPECT_PC = "respectpc";
    private static final String CAN_RELAY = "canrelay";
    private static final String RESERVED_FOR_NATIONAL_USE_VALUE_ADDRESS_INDICATOR = "reservedfornationalusevalue_addressindicator";
    private static final String SCCP_PROTOCOL_VERSION = "sccpProtocolVersion";
    private static final String PREVIEW_MODE = "previewMode";
    private static final String SST_TIMER_DURATION_MIN = "ssttimerduration_min";
    private static final String SST_TIMER_DURATION_MAX = "ssttimerduration_max";
    private static final String SST_TIMER_DURATION_INCREASE_FACTOR = "ssttimerduration_increasefactor";
    private static final String CONG_CONTROL_TIMER_A = "congControl_TIMER_A";
    private static final String CONG_CONTROL_TIMER_D = "congControl_TIMER_D";
    private static final String CONG_CONTROL_ALGO = "congControl_Algo";
    private static final String CONG_CONTROL_BLOCKING_OUTGOUNG_SCCP_MESSAGES = "congControl_blockingOutgoungSccpMessages";
    private static final String TIMER_EXECUTORS_THREAD_COUNT = "timerexecutors_threadcount";

    /**
     * Interval in milliseconds in which new coming for an affected PC MTP-STATUS messages will be logged
     */
    private static final int STATUS_MSG_LOGGING_INTERVAL_MILLISEC_CONG = 10000;
    private static final int STATUS_MSG_LOGGING_INTERVAL_MILLISEC_UNAVAIL = 100;

    protected static final XMLBinding binding = new XMLBinding();

    // If the XUDT message data length greater this value, segmentation is
    // needed
    protected int zMarginXudtMessage = 240;

    // sccp segmented message reassembling timeout
    protected int connEstTimerDelay = 15000;
    protected int iasTimerDelay = 7500 * 60;
    protected int iarTimerDelay = 16000 * 60;
    protected int relTimerDelay = 15000;
    protected int repeatRelTimerDelay = 15000;
    protected int intTimerDelay = 30000;
    protected int guardTimerDelay = 24000 * 60;
    protected int resetTimerDelay = 15000;
    protected int reassemblyTimerDelay = 15000;

    // Max available Sccp message data for all messages
    protected int maxDataMessage = 2560;
    // period logging warning in msec
    private int periodOfLogging = 60000;
    // remove PC from calledPartyAddress when sending to MTP3
    private boolean removeSpc = true;
    // respect point-code for outgoing messages
    //https://github.com/RestComm/jss7/issues/13
    private boolean respectPc = false;
    // can relay when relay with coupling condition is met
    private boolean canRelay = false;
    // min (starting) SST sending interval (millisec)
    protected int sstTimerDuration_Min = 10000;
    // max (after increasing) SST sending interval (millisec)
    protected int sstTimerDuration_Max = 600000;
    // multiplicator of SST sending interval (next interval will be greater the
    // current by sstTimerDuration_IncreaseFactor)
    // TODO: make it configurable
    protected double sstTimerDuration_IncreaseFactor = 1.5;
    // Which SCCP protocol version stack processes (ITU / ANSI)
    private SccpProtocolVersion sccpProtocolVersion = SccpProtocolVersion.ITU;

    // SCCP congestion control - the count of levels for restriction level - RLM
    protected int congControl_N = 8;
    // SCCP congestion control - the count of sublevels for restriction level - RSLM
    protected int congControl_M = 4;
    // Timer Ta value - started at next MTP-STATUS(cong) primitive coming; during this timer no more MTP-STATUS(cong) are
    // accepted
    protected int congControl_TIMER_A = 400; // 200
    // Timer Td value - started after last MTP-STATUS(cong) primitive coming; after end of this timer (without new coming
    // MTP-STATUS(cong)) RSLM will be reduced
    protected int congControl_TIMER_D = 2000; // 2000
    // sccp congestion control
    // international: international algorithm - only one level is provided by MTP3 level (in MTP-STATUS primitive). Each
    // MTP-STATUS increases N / M levels
    // levelDepended: MTP3 level (MTP-STATUS primitive) provides 3 levels of a congestion (1-3) and SCCP congestion will
    // increase to the
    // next level after MTP-STATUS next level increase (MTP-STATUS 1 to N up to 3, MTP-STATUS 2 to N up to 5, MTP-STATUS 3
    // to N up to 7)
    protected SccpCongestionControlAlgo congControl_Algo = SccpCongestionControlAlgo.international;
    // if true outgoing SCCP messages will be blocked (depending on message type, UDP messages from level N=6)
    protected boolean congControl_blockingOutgoungSccpMessages = false;

    // The count of threads that will be used for message delivering to
    // SccpListener's for SCCP user -> SCCP -> SCCP user transit (without MTP part)
    protected int deliveryTransferMessageThreadCount = 4;
    protected int timerExecutorsThreadCount = 10;

    private boolean previewMode = false;

    protected volatile State state = State.IDLE;

    // provider ref, this can be real provider or pipe, for tests.
    protected SccpProviderImpl sccpProvider;

    protected RouterImpl router;
    protected SccpResourceImpl sccpResource;

    protected MessageFactoryImpl messageFactory;

    protected SccpManagement sccpManagement;
    protected SccpRoutingControl sccpRoutingControl;

    protected FastMap<Integer, SccpConnectionImpl> connections = new FastMap<Integer, SccpConnectionImpl>().shared();

    protected int referenceNumberCounterMax = 0xffffff;

    protected FastMap<Integer, Mtp3UserPart> mtp3UserParts = new FastMap<Integer, Mtp3UserPart>();
    protected ScheduledExecutorService timerExecutors;
    protected FastMap<MessageReassemblyProcess, SccpSegmentableMessageImpl> reassemplyCache = new FastMap<MessageReassemblyProcess, SccpSegmentableMessageImpl>();

    // executors for delivering messages SCCP user -> SCCP -> SCCP user (for messages that are not from or to MTP part)
    protected ExecutorService[] msgDeliveryExecutors;
    protected int slsFilter = 0x0f;
    protected int[] slsTable = null;

    // protected int localSpc;
    // protected int ni = 2;

    protected final String name;

    protected final TextBuilder persistFile = TextBuilder.newInstance();
    protected String persistDir = null;

    protected boolean rspProhibitedByDefault;

    private volatile int segmentationLocalRef = 0;
    private volatile int slsCounter = 0;
    private volatile int selectorCounter = 0;
    protected volatile int referenceNumberCounter = 0;

    private FastMap<Integer, Date> lastCongNotice = new FastMap<Integer, Date>();
    private FastMap<Integer, Date> lastUserPartUnavailNotice = new FastMap<Integer, Date>();

    protected Scheduler scheduler;
    protected Ss7ExtSccpDetailedInterface ss7ExtSccpDetailedInterface;

    /*
     * For non-connection oriented protocol class usage
     */
    public SccpStackImpl(String name, Ss7ExtInterface ss7ExtInterface) {
        this(null, name, ss7ExtInterface);
    }

    public SccpStackImpl(Scheduler scheduler, String name, Ss7ExtInterface ss7ExtInterface) {
        this.scheduler = scheduler;

        Ss7ExtSccpInterface ss7ExtSccpInterface = null;
        if (ss7ExtInterface != null)
            ss7ExtSccpInterface = ss7ExtInterface.getSs7ExtSccpInterface();
        if (ss7ExtSccpInterface != null && ss7ExtSccpInterface instanceof Ss7ExtSccpDetailedInterface) {
            ss7ExtSccpDetailedInterface = (Ss7ExtSccpDetailedInterface) ss7ExtSccpInterface;
        } else {
            ss7ExtSccpDetailedInterface = new Ss7ExtSccpDetailedInterfaceDefault();
        }
        ss7ExtSccpDetailedInterface.init(this);

        binding.setClassAttribute(CLASS_ATTRIBUTE);

        this.name = name;
        this.logger = Logger.getLogger(SccpStackImpl.class.getCanonicalName() + "-" + this.name);

        this.messageFactory = new MessageFactoryImpl(this);
        this.sccpProvider = new SccpProviderImpl(this);

        this.state = State.CONFIGURED;
    }

    @Override
    public Ss7ExtSccpInterface getSs7ExtSccpInterface() {
        return ss7ExtSccpDetailedInterface;
    }

    public String getName() {
        return this.name;
    }

    public String getPersistDir() {
        return persistDir;
    }

    public void setPersistDir(String persistDir) {
        this.persistDir = persistDir;
    }

    public void setRspProhibitedByDefault(boolean rspProhibitedByDefault) {
        this.rspProhibitedByDefault = rspProhibitedByDefault;
    }

    public boolean isRspProhibitedByDefault() {
        return rspProhibitedByDefault;
    }

    public SccpProvider getSccpProvider() {
        return sccpProvider;
    }

    public SccpRoutingControl getSccpRoutingControl() {
        return sccpRoutingControl;
    }

    public Map<Integer, Mtp3UserPart> getMtp3UserParts() {
        return mtp3UserParts;
    }

    public void setMtp3UserParts(Map<Integer, Mtp3UserPart> mtp3UserPartsTemp) {
        if (mtp3UserPartsTemp != null) {
            synchronized (this) {
                FastMap<Integer, Mtp3UserPart> newMtp3UserPart = new FastMap<Integer, Mtp3UserPart>();
                newMtp3UserPart.putAll(mtp3UserPartsTemp);
                this.mtp3UserParts = newMtp3UserPart;
            }
        }
    }

    public Mtp3UserPart getMtp3UserPart(int id) {
        return mtp3UserParts.get(id);
    }

    public void setMtp3UserPart(int id, Mtp3UserPart mtp3UserPart) {
        if (mtp3UserPart == null) {
            this.removeMtp3UserPart(id);
        } else {
            synchronized (this) {
                FastMap<Integer, Mtp3UserPart> newMtp3UserPart = new FastMap<Integer, Mtp3UserPart>();
                newMtp3UserPart.putAll(this.mtp3UserParts);
                newMtp3UserPart.put(id, mtp3UserPart);
                this.mtp3UserParts = newMtp3UserPart;
            }
        }
    }

    public void removeMtp3UserPart(int id) {
        synchronized (this) {
            FastMap<Integer, Mtp3UserPart> newMtp3UserPart = new FastMap<Integer, Mtp3UserPart>();
            newMtp3UserPart.putAll(this.mtp3UserParts);
            newMtp3UserPart.remove(id);
            this.mtp3UserParts = newMtp3UserPart;
        }
    }

    public void setRemoveSpc(boolean removeSpc) throws Exception {
        if (!this.isStarted())
            throw new Exception("RemoveSpc parameter can be updated only when SCCP stack is running");

        this.removeSpc = removeSpc;

        this.store();
    }

    public void setRespectPc(boolean respectPc) throws Exception {
        if (!this.isStarted())
            throw new Exception("RespectPc parameter can be updated only when SCCP stack is running");

        this.respectPc = respectPc;

        this.store();
    }

    public void setCanRelay(boolean canRelay) throws Exception {
        if (!this.isStarted())
            throw new Exception("CanRelay parameter can be updated only when SCCP stack is running");

        this.canRelay = canRelay;

        this.store();
    }

    public void setSccpProtocolVersion(SccpProtocolVersion sccpProtocolVersion) throws Exception {
        if (!this.isStarted())
            throw new Exception("SccpProtocolVersion parameter can be updated only when SCCP stack is running");

        if (sccpProtocolVersion != null)
            this.sccpProtocolVersion = sccpProtocolVersion;

        this.store();
    }

    public void setPreviewMode(boolean previewMode) throws Exception {
        if (!this.isStarted())
            throw new Exception("PreviewMode parameter can be updated only when SCCP stack is running");

        this.previewMode = previewMode;

        this.store();
    }

    public int getDeliveryMessageThreadCount() {
        return this.deliveryTransferMessageThreadCount;
    }

    public void setDeliveryMessageThreadCount(int deliveryMessageThreadCount) throws Exception {
        if (this.isStarted())
            throw new Exception("DeliveryMessageThreadCount parameter can be updated only when SCCP stack is NOT running");

        if (deliveryMessageThreadCount > 0 && deliveryMessageThreadCount <= 100)
            this.deliveryTransferMessageThreadCount = deliveryMessageThreadCount;
    }

    public int getTimerExecutorsThreadCount() {
        return timerExecutorsThreadCount;
    }

    public void setTimerExecutorsThreadCount(int timerExecutorsThreadCount) throws Exception {
        if (this.isStarted())
            throw new Exception("ConnectionTimersThreadCount parameter can be updated only when SCCP stack is NOT running");

        if (timerExecutorsThreadCount < 1) {
            timerExecutorsThreadCount = 1;
        }
        if (timerExecutorsThreadCount > 1000) {
            timerExecutorsThreadCount = 1000;
        }
        this.timerExecutorsThreadCount = timerExecutorsThreadCount;
    }

    public void setSstTimerDuration_Min(int sstTimerDuration_Min) throws Exception {
        if (!this.isStarted())
            throw new Exception("SstTimerDuration_Min parameter can be updated only when SCCP stack is running");

        // 5-10 seconds
        if (sstTimerDuration_Min < 5000)
            sstTimerDuration_Min = 5000;
        if (sstTimerDuration_Min > 10000)
            sstTimerDuration_Min = 10000;
        this.sstTimerDuration_Min = sstTimerDuration_Min;

        this.store();
    }

    public void setSstTimerDuration_Max(int sstTimerDuration_Max) throws Exception {
        if (!this.isStarted())
            throw new Exception("SstTimerDuration_Max parameter can be updated only when SCCP stack is running");

        // 10-20 minutes
        if (sstTimerDuration_Max < 600000)
            sstTimerDuration_Max = 600000;
        if (sstTimerDuration_Max > 1200000)
            sstTimerDuration_Max = 1200000;
        this.sstTimerDuration_Max = sstTimerDuration_Max;

        this.store();
    }

    public void setSstTimerDuration_IncreaseFactor(double sstTimerDuration_IncreaseFactor) throws Exception {
        if (!this.isStarted())
            throw new Exception("SstTimerDuration_IncreaseFactor parameter can be updated only when SCCP stack is running");

        // acceptable factor from 1 to 4
        if (sstTimerDuration_IncreaseFactor < 1)
            sstTimerDuration_IncreaseFactor = 1;
        if (sstTimerDuration_IncreaseFactor > 4)
            sstTimerDuration_IncreaseFactor = 4;
        this.sstTimerDuration_IncreaseFactor = sstTimerDuration_IncreaseFactor;

        this.store();
    }


    public int getCongControlTIMER_A() {
        return congControl_TIMER_A;
    }

    public void setCongControlTIMER_A(int value) throws Exception {
        if (!this.isStarted())
            throw new Exception("CongControlTIMER_A parameter can be updated only when SCCP stack is running");

        if (value < 60)
            value = 60;
        if (value > 1000)
            value = 1000;

        congControl_TIMER_A = value;

        this.store();
    }


    public int getCongControlTIMER_D() {
        return congControl_TIMER_D;
    }

    public void setCongControlTIMER_D(int value) throws Exception {
        if (!this.isStarted())
            throw new Exception("CongControlTIMER_D parameter can be updated only when SCCP stack is running");

        if (value < 500)
            value = 500;
        if (value > 10000)
            value = 10000;

        congControl_TIMER_D = value;

        this.store();
    }

    public int getCongControlN() {
        return congControl_N;
    }

    public void setCongControlN(int value) {
        congControl_N = value;

        this.store();
    }

    public int getCongControlM() {
        return congControl_M;
    }

    public void setCongControlM(int value) {
        congControl_M = value;

        this.store();
    }

    public SccpCongestionControlAlgo getCongControl_Algo() {
        return congControl_Algo;
    }

    public void setCongControl_Algo(SccpCongestionControlAlgo value) throws Exception {
        if (!this.isStarted())
            throw new Exception("CongControl_Algo parameter can be updated only when SCCP stack is running");

        if (value != null)
            congControl_Algo = value;

        this.store();
    }

    public boolean isCongControl_blockingOutgoungSccpMessages() {
        return congControl_blockingOutgoungSccpMessages;
    }

    public void setCongControl_blockingOutgoungSccpMessages(boolean value) throws Exception {
        if (!this.isStarted())
            throw new Exception("CongControl_blockingOutgoungSccpMessages parameter can be updated only when SCCP stack is running");

        congControl_blockingOutgoungSccpMessages = value;

        this.store();
    }

    public boolean isRemoveSpc() {
        return this.removeSpc;
    }

    public boolean isRespectPc() {
        return this.respectPc;
    }

    public boolean isCanRelay() {
        return this.canRelay;
    }

    public SccpProtocolVersion getSccpProtocolVersion() {
        return this.sccpProtocolVersion;
    }

    public boolean isPreviewMode() {
        return this.previewMode;
    }

    public int getSstTimerDuration_Min() {
        return this.sstTimerDuration_Min;
    }

    public int getSstTimerDuration_Max() {
        return this.sstTimerDuration_Max;
    }

    public double getSstTimerDuration_IncreaseFactor() {
        return this.sstTimerDuration_IncreaseFactor;
    }

    public int getZMarginXudtMessage() {
        return zMarginXudtMessage;
    }

    public void setZMarginXudtMessage(int zMarginXudtMessage) throws Exception {
        if (!this.isStarted())
            throw new Exception("ZMarginXudtMessage parameter can be updated only when SCCP stack is running");

        // value from 160 to 255 bytes
        if (zMarginXudtMessage < 160)
            zMarginXudtMessage = 160;
        if (zMarginXudtMessage > 255)
            zMarginXudtMessage = 255;
        this.zMarginXudtMessage = zMarginXudtMessage;

        this.store();
    }

    public int getMaxDataMessage() {
        return maxDataMessage;
    }

    public void setMaxDataMessage(int maxDataMessage) throws Exception {
        if (!this.isStarted())
            throw new Exception("MaxDataMessage parameter can be updated only when SCCP stack is running");

        // from 2560 to 3952 bytes
        if (maxDataMessage < 2560)
            maxDataMessage = 2560;
        if (maxDataMessage > 3952)
            maxDataMessage = 3952;
        this.maxDataMessage = maxDataMessage;

        this.store();
    }

    public int getConnEstTimerDelay() {
        return this.connEstTimerDelay;
    }

    public void setConnEstTimerDelay(int connEstTimerDelay) throws Exception {
        if (!this.isStarted())
            throw new Exception("ConnEstTimerDelay parameter can be updated only when SCCP stack is running");

        // from 1 to 2 minutes
        if (connEstTimerDelay < 60000)
            connEstTimerDelay = 60000;
        if (connEstTimerDelay > 120000)
            connEstTimerDelay = 120000;
        this.connEstTimerDelay = connEstTimerDelay;

        this.store();
    }

    public int getIasTimerDelay() {
        return this.iasTimerDelay;
    }

    public void setIasTimerDelay(int iasTimerDelay) throws Exception {
        if (!this.isStarted())
            throw new Exception("IasTimerDelay parameter can be updated only when SCCP stack is running");

        // from 5 to 10 minutes
        if (iasTimerDelay < 300000)
            iasTimerDelay = 300000;
        if (iasTimerDelay > 600000)
            iasTimerDelay = 600000;
        this.iasTimerDelay = iasTimerDelay;

        this.store();
    }

    public int getIarTimerDelay() {
        return this.iarTimerDelay;
    }

    public void setIarTimerDelay(int iarTimerDelay) throws Exception {
        this.iarTimerDelay = iarTimerDelay;

        if (!this.isStarted())
            throw new Exception("IarTimerDelay parameter can be updated only when SCCP stack is running");

        // from 11 to 21 minutes
        if (iarTimerDelay < 660000)
            iarTimerDelay = 660000;
        if (iarTimerDelay > 1260000)
            iarTimerDelay = 1260000;
        this.iarTimerDelay = iarTimerDelay;

        this.store();
    }

    public int getRelTimerDelay() {
        return this.relTimerDelay;
    }

    public void setRelTimerDelay(int relTimerDelay) throws Exception {
        if (!this.isStarted())
            throw new Exception("RelTimerDelay parameter can be updated only when SCCP stack is running");

        // from 10 to 20 seconds
        if (relTimerDelay < 10000)
            relTimerDelay = 10000;
        if (relTimerDelay > 20000)
            relTimerDelay = 20000;
        this.relTimerDelay = relTimerDelay;

        this.store();
    }

    public int getRepeatRelTimerDelay() {
        return this.repeatRelTimerDelay;
    }

    public void setRepeatRelTimerDelay(int repeatRelTimerDelay) throws Exception {
        if (!this.isStarted())
            throw new Exception("RepeatRelTimerDelay parameter can be updated only when SCCP stack is running");

        // from 10 to 20 seconds
        if (repeatRelTimerDelay < 10000)
            repeatRelTimerDelay = 10000;
        if (repeatRelTimerDelay > 20000)
            repeatRelTimerDelay = 20000;
        this.repeatRelTimerDelay = repeatRelTimerDelay;

        this.store();
    }

    public int getIntTimerDelay() {
        return this.intTimerDelay;
    }

    public void setIntTimerDelay(int intTimerDelay) throws Exception {
        if (!this.isStarted())
            throw new Exception("IntTimerDelay parameter can be updated only when SCCP stack is running");

        // extending to 1 minute
        if (intTimerDelay < 0)
            intTimerDelay = 0;
        if (intTimerDelay > 60000)
            intTimerDelay = 60000;
        this.intTimerDelay = intTimerDelay;

        this.store();
    }

    public int getGuardTimerDelay() {
        return this.guardTimerDelay;
    }

    public void setGuardTimerDelay(int guardTimerDelay) throws Exception {
        if (!this.isStarted())
            throw new Exception("GuardTimerDelay parameter can be updated only when SCCP stack is running");

        // from 23 to 25 minutes
        if (guardTimerDelay < 1380000)
            guardTimerDelay = 1380000;
        if (guardTimerDelay > 1500000)
            guardTimerDelay = 1500000;
        this.guardTimerDelay = guardTimerDelay;

        this.store();
    }

    public int getResetTimerDelay() {
        return this.resetTimerDelay;
    }

    public void setResetTimerDelay(int resetTimerDelay) throws Exception {
        if (!this.isStarted())
            throw new Exception("ResetTimerDelay parameter can be updated only when SCCP stack is running");

        // from 10 to 20 seconds
        if (resetTimerDelay < 10000)
            resetTimerDelay = 10000;
        if (resetTimerDelay > 20000)
            resetTimerDelay = 20000;
        this.resetTimerDelay = resetTimerDelay;

        this.store();
    }

    public int getPeriodOfLogging() {
        return periodOfLogging;
    }

    public void setPeriodOfLogging(int periodOfLogging) throws Exception {
        if (!this.isStarted())
            throw new Exception("periodOfLogging parameter can be updated only when SCCP stack is running");

        this.periodOfLogging = periodOfLogging;

        this.store();
    }

    public int getReassemblyTimerDelay() {
        return this.reassemblyTimerDelay;
    }

    public void setReassemblyTimerDelay(int reassemblyTimerDelay) throws Exception {
        if (!this.isStarted())
            throw new Exception("ReassemblyTimerDelay parameter can be updated only when SCCP stack is running");

        // from 10 to 20 seconds
        if (reassemblyTimerDelay < 10000)
            reassemblyTimerDelay = 10000;
        if (reassemblyTimerDelay > 20000)
            reassemblyTimerDelay = 20000;
        this.reassemblyTimerDelay = reassemblyTimerDelay;

        this.store();
    }

    public synchronized int newSegmentationLocalRef() {
        return ++this.segmentationLocalRef;
    }

    public synchronized int newSls() {
        if (++this.slsCounter > 255)
            this.slsCounter = 0;
        return this.slsCounter;
    }

    public synchronized boolean newSelector() {
        if (++this.selectorCounter > 1)
            this.selectorCounter = 0;
        return (this.selectorCounter == 1);
    }

    protected void createSLSTable(int maxSls, int minimumBoundThread) {
        int stream = 0;
        for (int i = 0; i < maxSls; i++) {
            if (stream >= minimumBoundThread) {
                stream = 0;
            }
            slsTable[i] = stream++;
        }
    }

    public void start() throws IllegalStateException {
        logger.info("Starting ...");

        ss7ExtSccpDetailedInterface.startExtBefore(persistDir, this.name);

        this.persistFile.clear();

        if (persistDir != null) {
            this.persistFile.append(persistDir).append(File.separator).append(this.name).append("_").append(PERSIST_FILE_NAME);
        } else {
            persistFile.append(System.getProperty(SCCP_MANAGEMENT_PERSIST_DIR_KEY, System.getProperty(USER_DIR_KEY)))
                    .append(File.separator).append(this.name).append("_").append(PERSIST_FILE_NAME);
        }

        logger.info(String.format("SCCP Management configuration file path %s", persistFile.toString()));

        try {
            this.load();
        } catch (FileNotFoundException e) {
            logger.warn(String.format("Failed to load the Sccp Management configuration file. \n%s", e.getMessage()));
        }

        // FIXME: make this configurable
        // FIXME: move creation to constructor ?
        this.sccpManagement = new SccpManagement(name, sccpProvider, this);
        this.sccpRoutingControl = new SccpRoutingControl(sccpProvider, this);

        this.sccpManagement.setSccpRoutingControl(sccpRoutingControl);
        this.sccpRoutingControl.setSccpManagement(sccpManagement);

        this.router = new RouterImpl(this.name, this);
        this.router.setPersistDir(this.persistDir);
        this.router.start();

        ss7ExtSccpDetailedInterface.startExtAfter(this.router, this.sccpManagement);

        this.sccpResource = new SccpResourceImpl(this.name, this.rspProhibitedByDefault, ss7ExtSccpDetailedInterface);
        this.sccpResource.setPersistDir(this.persistDir);
        this.sccpResource.start();

        logger.info("Starting routing engine...");
        this.sccpRoutingControl.start();
        logger.info("Starting management ...");
        this.sccpManagement.start();
        logger.info("Starting MSU handler...");

        this.timerExecutors = Executors.newScheduledThreadPool(timerExecutorsThreadCount);

        // initiating of SCCP delivery executors
        // TODO: we do it for ITU standard, may be we may configure it for other standard's (different SLS count) maxSls and
        // slsFilter values initiating
        int maxSls = 16;
        slsFilter = 0x0f;
        this.slsTable = new int[maxSls];
        this.createSLSTable(maxSls, this.deliveryTransferMessageThreadCount);
        this.msgDeliveryExecutors = new ExecutorService[this.deliveryTransferMessageThreadCount];
        for (int i = 0; i < this.deliveryTransferMessageThreadCount; i++) {
            this.msgDeliveryExecutors[i] = Executors.newFixedThreadPool(1, new DefaultThreadFactory(
                    "SccpTransit-DeliveryExecutor-" + i));
        }

        for (FastMap.Entry<Integer, Mtp3UserPart> e = this.mtp3UserParts.head(), end = this.mtp3UserParts.tail(); (e = e
                .getNext()) != end;) {
            Mtp3UserPart mup = e.getValue();
            mup.addMtp3UserPartListener(this);
        }

        for (SccpManagementEventListener lstr : this.sccpProvider.managementEventListeners) {
            try {
                lstr.onServiceStarted();
            } catch (Throwable ee) {
                logger.error("Exception while invoking onServiceStarted", ee);
            }
        }

        this.state = State.RUNNING;
    }

    public void stop() {
        logger.info("Stopping ...");
        // stateLock.lock();
        // try
        // {
        this.state = State.IDLE;
        // executor = null;
        //
        // layer3exec = null;

        ss7ExtSccpDetailedInterface.stopExt();

        if (this.msgDeliveryExecutors != null) {
            for (ExecutorService es : this.msgDeliveryExecutors) {
                es.shutdown();
            }
            this.msgDeliveryExecutors = null;
        }

        for (SccpManagementEventListener lstr : this.sccpProvider.managementEventListeners) {
            try {
                lstr.onServiceStopped();
            } catch (Throwable ee) {
                logger.error("Exception while invoking onServiceStopped", ee);
            }
        }

        for (FastMap.Entry<Integer, Mtp3UserPart> e = this.mtp3UserParts.head(), end = this.mtp3UserParts.tail(); (e = e
                .getNext()) != end;) {
            Mtp3UserPart mup = e.getValue();
            mup.removeMtp3UserPartListener(this);
        }

        logger.info("Stopping management...");
        this.sccpManagement.stop();
        logger.info("Stopping routing engine...");
        this.sccpRoutingControl.stop();
        logger.info("Stopping MSU handler...");

        this.sccpResource.stop();

        this.router.stop();

        synchronized (reassemplyCache) {
            this.timerExecutors.shutdownNow();
            reassemplyCache.clear();
        }

        this.store();

        // }finally
        // {
        // stateLock.unlock();
        // }
    }

    public boolean isStarted() {
        return this.state == State.RUNNING;
    }

    public Router getRouter() {
        return this.router;
    }

    public SccpResource getSccpResource() {
        return sccpResource;
    }

    public SccpConnectionImpl getConnection(LocalReference number) {
        if (number == null) {
            logger.error("Reference number can't be null");
            throw new IllegalArgumentException("Reference number can't be null");
        }
        return connections.get(number.getValue());
    }

    public int getConnectionsNumber() {
        return connections.size();
    }

    protected enum State {
        IDLE, CONFIGURED, RUNNING;
    }

    public SccpConnectionImpl newConnection(int localSsn, ProtocolClass protocol) throws MaxConnectionCountReached {
        SccpConnectionImpl conn;
        Integer refNumber = newReferenceNumber();

        if (protocol.getProtocolClass() == 2) {
            conn = new SccpConnectionImpl(localSsn, new LocalReferenceImpl(refNumber), protocol, this, sccpRoutingControl);
        } else if (protocol.getProtocolClass() == 3) {
            conn = new SccpConnectionWithFlowControlImpl(localSsn, new LocalReferenceImpl(refNumber), protocol, this, sccpRoutingControl);
        } else {
            logger.error(String.format("Unsupported connection class %d", protocol.getProtocolClass()));
            throw new IllegalArgumentException();
        }

        connections.put(refNumber, conn);
        return conn;
    }

    protected void removeConnection(LocalReference ref) {
        SccpConnectionImpl conn = connections.get(ref.getValue());
        if (conn != null) {
            connections.remove(ref.getValue());

            conn.stopTimers();
            conn.setState(SccpConnectionState.CLOSED);
        }
    }

    protected int newReferenceNumber() throws MaxConnectionCountReached {
        synchronized (this) {
            if (referenceNumberCounter++ > referenceNumberCounterMax) {
                referenceNumberCounter = 0;
            }

            // 0 and reference numbers values which are > 0
            if (connections.size() >= referenceNumberCounterMax + 1) {
                logger.error(String.format("Can't open more connections than %d", referenceNumberCounterMax + 1));
                throw new MaxConnectionCountReached(String.format("Can't open more connections than %d", referenceNumberCounterMax + 1));
            }

            while (connections.keySet().contains(referenceNumberCounter)) {
                referenceNumberCounter++;
            }
            return referenceNumberCounter;
        }

    }

    protected void send(SccpDataNoticeTemplateMessageImpl message) throws Exception {

        if (this.state != State.RUNNING) {
            logger.error("Trying to send SCCP message from SCCP user but SCCP stack is not RUNNING");
            return;
        }

        if (message.getCalledPartyAddress() == null || message.getCallingPartyAddress() == null || message.getData() == null
                || message.getData().length == 0) {
            logger.error("Message to send must has filled CalledPartyAddress, CallingPartyAddress and data fields");
            throw new IOException("Message to send must has filled CalledPartyAddress, CallingPartyAddress and data fields");
        }

        try {
            this.sccpRoutingControl.routeMssgFromSccpUser(message);
        } catch (Exception e) {
            // log here Exceptions from MTP3 level
            logger.error("IOException when sending the message to MTP3 level: " + e.getMessage(), e);
            throw e;
        }
    }

    protected int getMaxUserDataLength(SccpAddress calledPartyAddress, SccpAddress callingPartyAddress, int msgNetworkId) {

        GlobalTitle gt = calledPartyAddress.getGlobalTitle();
        int dpc = calledPartyAddress.getSignalingPointCode();
        int ssn = calledPartyAddress.getSubsystemNumber();

        if (calledPartyAddress.getAddressIndicator().isPCPresent()) {
            if (this.router.spcIsLocal(dpc)) {
                if (ssn > 0) {
                    // local destination - unlimited length
                    return this.getMaxDataMessage();
                } else if (gt != null) {
                    return getMaxUserDataLengthForGT(calledPartyAddress, callingPartyAddress, msgNetworkId);
                } else {
                    return 0;
                }
            } else {
                return getMaxUserDataLengthForDpc(dpc, calledPartyAddress, callingPartyAddress);
            }
        } else {
            if (gt != null) {
                return getMaxUserDataLengthForGT(calledPartyAddress, callingPartyAddress, msgNetworkId);
            } else {
                return 0;
            }
        }
    }

    private int getMaxUserDataLengthForDpc(int dpc, SccpAddress calledPartyAddress, SccpAddress callingPartyAddress) {

        LongMessageRule lmr = this.router.findLongMessageRule(dpc);
        LongMessageRuleType lmrt = LongMessageRuleType.LONG_MESSAGE_FORBBIDEN;
        if (lmr != null)
            lmrt = lmr.getLongMessageRuleType();
        Mtp3ServiceAccessPoint sap = this.router.findMtp3ServiceAccessPoint(dpc, 0);
        if (sap == null) {
            return 0;
        }
        Mtp3UserPart mup = this.getMtp3UserPart(sap.getMtp3Id());
        if (mup == null) {
            return 0;
        }

        try {
            int fieldsLen = 0;
            byte[] cdp = ((SccpAddressImpl) calledPartyAddress).encode(isRemoveSpc(), this.getSccpProtocolVersion());
            byte[] cnp = ((SccpAddressImpl) callingPartyAddress).encode(isRemoveSpc(), this.getSccpProtocolVersion());
            switch (lmrt) {
                case LONG_MESSAGE_FORBBIDEN:
                    fieldsLen = calculateUdtFieldsLengthWithoutData(cdp.length, cnp.length);
                    break;
                case LUDT_ENABLED:
                case LUDT_ENABLED_WITH_SEGMENTATION:
                    fieldsLen = calculateLudtFieldsLengthWithoutData(cdp.length, cnp.length, true, true);
                    break;
                case XUDT_ENABLED:
                    fieldsLen = calculateXudtFieldsLengthWithoutData(cdp.length, cnp.length, true, true);
                    int fieldsLen2 = calculateXudtFieldsLengthWithoutData2(cdp.length, cnp.length);
                    if (fieldsLen > fieldsLen2)
                        fieldsLen = fieldsLen2;
                    break;
            }

            int availLen = mup.getMaxUserDataLength(dpc) - fieldsLen;
            if ((lmrt == LongMessageRuleType.LONG_MESSAGE_FORBBIDEN || lmrt == LongMessageRuleType.XUDT_ENABLED)
                    && availLen > 255)
                availLen = 255;
            if (lmrt == LongMessageRuleType.XUDT_ENABLED)
                availLen *= 16;
            if (availLen > this.getMaxDataMessage())
                availLen = this.getMaxDataMessage();
            return availLen;

        } catch (Exception e) {
            // this can not occur
            // dont be so sure!
            e.printStackTrace();
            return 0;
        }
    }

    private int getMaxUserDataLengthForGT(SccpAddress calledPartyAddress, SccpAddress callingPartyAddress, int msgNetworkId) {
        int dpc = ss7ExtSccpDetailedInterface.findDpsForAddresses(calledPartyAddress, callingPartyAddress, msgNetworkId);

        return getMaxUserDataLengthForDpc(dpc, calledPartyAddress, callingPartyAddress);
    }

    protected void broadcastChangedSsnState(int affectedSsn, boolean inService) {
        this.sccpManagement.broadcastChangedSsnState(affectedSsn, inService);
    }

    public void removeAllResourses() {

        if (this.state != State.RUNNING) {
            return;
        }

        this.router.removeAllResourses();
        this.sccpResource.removeAllResourses();

        for (SccpManagementEventListener lstr : this.sccpProvider.managementEventListeners) {
            try {
                lstr.onRemoveAllResources();
            } catch (Throwable ee) {
                logger.error("Exception while invoking onRemoveAllResources", ee);
            }
        }

        ss7ExtSccpDetailedInterface.removeAllResourses();
    }

    public void onMtp3PauseMessage(Mtp3PausePrimitive msg) {

        logger.warn(String.format("Rx : %s", msg));

        if (this.state != State.RUNNING) {
            logger.error("Cannot consume MTP3 PASUE message as SCCP stack is not RUNNING");
            return;
        }

        sccpManagement.handleMtp3Pause(msg.getAffectedDpc());
    }

    public void onMtp3ResumeMessage(Mtp3ResumePrimitive msg) {
        logger.warn(String.format("Rx : %s", msg));

        if (this.state != State.RUNNING) {
            logger.error("Cannot consume MTP3 RESUME message as SCCP stack is not RUNNING");
            return;
        }

        sccpManagement.handleMtp3Resume(msg.getAffectedDpc());
    }

    public void onMtp3StatusMessage(Mtp3StatusPrimitive msg) {
        int affectedDpc = msg.getAffectedDpc();

        // we are making of announcing of MTP-STATUS only each 10 seconds
        Date lastNotice;
        if (msg.getCause() == Mtp3StatusCause.SignallingNetworkCongested) {
            lastNotice = lastCongNotice.get(affectedDpc);
            if (lastNotice == null) {
                lastCongNotice.put(affectedDpc, new Date());
                logger.warn(String.format("Rx : %s  (one message in %d seconds)", msg, STATUS_MSG_LOGGING_INTERVAL_MILLISEC_UNAVAIL));
            } else {
                if (System.currentTimeMillis() - lastNotice.getTime() > STATUS_MSG_LOGGING_INTERVAL_MILLISEC_CONG) {
                    lastNotice.setTime(System.currentTimeMillis());
                    logger.warn(String.format("Rx : %s (one message in %d seconds)", msg, STATUS_MSG_LOGGING_INTERVAL_MILLISEC_UNAVAIL));
                }
            }
        } else {
            lastNotice = lastUserPartUnavailNotice.get(affectedDpc);
            if (lastNotice == null) {
                lastUserPartUnavailNotice.put(affectedDpc, new Date());
                logger.warn(String.format("Rx : %s (one message in %d seconds)", msg, STATUS_MSG_LOGGING_INTERVAL_MILLISEC_UNAVAIL));
            } else {
                if (System.currentTimeMillis() - lastNotice.getTime() > STATUS_MSG_LOGGING_INTERVAL_MILLISEC_UNAVAIL) {
                    lastNotice.setTime(System.currentTimeMillis());
                    logger.warn(String.format("Rx : %s (one message in %d seconds)", msg, STATUS_MSG_LOGGING_INTERVAL_MILLISEC_UNAVAIL));
                }
            }
        }

        if (this.state != State.RUNNING) {
            logger.error("Cannot consume MTP3 STATUS message as SCCP stack is not RUNNING");
            return;
        }

        sccpManagement.handleMtp3Status(msg.getCause(), affectedDpc, msg.getCongestionLevel());
    }

    @Override
    public void onMtp3EndCongestionMessage(Mtp3EndCongestionPrimitive msg) {
        int affectedDpc = msg.getAffectedDpc();

        logger.warn(String.format("Rx : %s", msg));

        sccpManagement.handleMtp3EndCongestion(affectedDpc);
    }

    public void onMtp3TransferMessage(Mtp3TransferPrimitive mtp3Msg) {

        if (this.state != State.RUNNING) {
            logger.error("Received MTP3TransferPrimitive from lower layer but SCCP stack is not RUNNING");
            return;
        }

        SccpMessageImpl msg = null;
        int dpc = mtp3Msg.getDpc();
        int opc = mtp3Msg.getOpc();

        try {
            // checking if incoming dpc is local
            if (!this.isPreviewMode() && !this.router.spcIsLocal(dpc)) {

                // incoming dpc is not local - trying to find the target SAP and
                // send a message to MTP3 (MTP transit function)
                int sls = mtp3Msg.getSls();

                RemoteSignalingPointCode remoteSpc = this.getSccpResource().getRemoteSpcByPC(dpc);
                Mtp3ServiceAccessPoint sap = this.router.findMtp3ServiceAccessPoint(opc, sls);
                if (remoteSpc == null) {
                    if (logger.isEnabledFor(Level.WARN)) {
                        logger.warn(String.format("Incoming Mtp3 Message for nonlocal dpc=%d. But RemoteSpc is not found", dpc));
                    }
                    return;
                }
                if (remoteSpc.isRemoteSpcProhibited()) {
                    if (logger.isEnabledFor(Level.WARN)) {
                        logger.warn(String
                                .format("Incoming Mtp3 Message for nonlocal dpc=%d. But RemoteSpc is Prohibited", dpc));
                    }
                    // TODO: ***** SSP should we send SSP message to a peer ?
                    return;
                }
                if (remoteSpc.getCurrentRestrictionLevel() > 1) {
                    if (logger.isEnabledFor(Level.WARN)) {
                        logger.warn(String
                                .format("Incoming Mtp3 Message for nonlocal dpc=%d. But RemoteSpc is Congested", dpc));
                    }
                    // TODO: ***** SSC should we send SSC message to a peer ?
                    return;
                }
                Mtp3ServiceAccessPoint sap2 = this.router.findMtp3ServiceAccessPoint(dpc, sls);
                if (sap2 == null) {
                    if (logger.isEnabledFor(Level.WARN)) {
                        logger.warn(String.format("Incoming Mtp3 Message for nonlocal dpc=%d / sls=%d. But SAP is not found",
                                dpc, sls));
                    }
                    return;
                }
                Mtp3UserPart mup = this.getMtp3UserPart(sap2.getMtp3Id());
                if (mup == null) {
                    if (logger.isEnabledFor(Level.WARN)) {
                        logger.warn(String.format(
                                "Incoming Mtp3 Message for nonlocal dpc=%d / sls=%d. no matching Mtp3UserPart found", dpc, sls));
                    }
                    return;
                }

                mup.sendMessage(mtp3Msg);
                return;
            }

            // process only SCCP messages
            if (mtp3Msg.getSi() != Mtp3._SI_SERVICE_SCCP) {
                logger.warn(String
                        .format("Received Mtp3TransferPrimitive from lower layer with Service Indicator=%d which is not SCCP. Dropping this message",
                                mtp3Msg.getSi()));
                return;
            }

            // decoding of a message
            ByteArrayInputStream bais = new ByteArrayInputStream(mtp3Msg.getData());
            DataInputStream in = new DataInputStream(bais);
            int mt = in.readUnsignedByte();
            msg = ((MessageFactoryImpl) sccpProvider.getMessageFactory()).createMessage(mt, mtp3Msg.getOpc(), mtp3Msg.getDpc(), mtp3Msg.getSls(), in,
                    this.sccpProtocolVersion, 0);

            // finding sap and networkId for a message
            dpc = mtp3Msg.getDpc();
            opc = mtp3Msg.getOpc();
            String localGtDigits = null;
            if (msg instanceof SccpAddressedMessageImpl) {
                SccpAddressedMessageImpl msgAddr = (SccpAddressedMessageImpl) msg;
                SccpAddress addr = msgAddr.getCalledPartyAddress();
                if (addr != null) {
                    GlobalTitle gt = addr.getGlobalTitle();
                    if (gt != null) {
                        localGtDigits = gt.getDigits();
                    }
                }
            }
            Mtp3ServiceAccessPoint sap = this.router.findMtp3ServiceAccessPointForIncMes(dpc, opc, localGtDigits);
            int networkId = 0;
            if (sap == null) {
                if (logger.isEnabledFor(Level.WARN)) {
                    logger.warn(String.format("Incoming Mtp3 Message for local address for localPC=%d, remotePC=%d, sls=%d. But SAP is not found for localPC", dpc, opc, mtp3Msg.getSls()));
                }
            } else {
                networkId = sap.getNetworkId();
            }
            msg.setNetworkId(networkId);

            if (logger.isDebugEnabled()) {
                logger.debug(String.format("Rx : SCCP message from MTP %s", msg));
            }

            // when segmented messages - make a reassembly operation
            if (msg instanceof SccpSegmentableMessageImpl) {
                SccpSegmentableMessageImpl sgmMsg = (SccpSegmentableMessageImpl) msg;
                SegmentationImpl segm = (SegmentationImpl) sgmMsg.getSegmentation();
                if (segm != null) {
                    // segmentation info is present - segmentation is possible
                    if (segm.isFirstSegIndication() && segm.getRemainingSegments() == 0) {

                        // the single segment - no reassembly is needed
                        sgmMsg.setReceivedSingleSegment();
                    } else {

                        // multiple segments - reassembly is needed
                        if (segm.isFirstSegIndication()) {

                            // first segment
                            sgmMsg.setReceivedFirstSegment();
                            MessageReassemblyProcess msp = new MessageReassemblyProcess(segm.getSegmentationLocalRef(),
                                    sgmMsg.getCallingPartyAddress());
                            synchronized (this.reassemplyCache) {
                                this.reassemplyCache.put(msp, sgmMsg);
                            }
                            sgmMsg.setMessageReassemblyProcess(msp);
                            msp.startTimer();
                            return;
                        } else {

                            // nonfirst segment
                            MessageReassemblyProcess msp = new MessageReassemblyProcess(segm.getSegmentationLocalRef(),
                                    sgmMsg.getCallingPartyAddress());
                            SccpSegmentableMessageImpl sgmMsgFst = null;
                            synchronized (this.reassemplyCache) {
                                sgmMsgFst = this.reassemplyCache.get(msp);
                            }
                            if (sgmMsgFst == null) {
                                // previous segments cache is not found -
                                // discard a segment
                                if (logger.isEnabledFor(Level.WARN)) {
                                    logger.warn(String
                                            .format("Reassembly function failure: received a non first segment without the first segement having recieved. SccpMessageSegment=%s",
                                                    msg));
                                }
                                return;
                            }
                            if (sgmMsgFst.getRemainingSegments() - 1 != segm.getRemainingSegments()) {
                                // segments bad order
                                synchronized (this.reassemplyCache) {
                                    this.reassemplyCache.remove(msp);
                                    MessageReassemblyProcess mspMain = sgmMsgFst.getMessageReassemblyProcess();
                                    if (mspMain != null)
                                        mspMain.stopTimer();
                                }
                                if (logger.isEnabledFor(Level.WARN)) {
                                    logger.warn(String
                                            .format("Reassembly function failure: when receiving a next segment message order is missing. SccpMessageSegment=%s",
                                                    msg));
                                }
                                this.sccpRoutingControl.sendSccpError(sgmMsgFst, ReturnCauseValue.CANNOT_REASEMBLE, null);
                                return;
                            }

                            if (sgmMsgFst.getRemainingSegments() == 1) {
                                // last segment
                                synchronized (this.reassemplyCache) {
                                    MessageReassemblyProcess mspMain = sgmMsgFst.getMessageReassemblyProcess();
                                    if (mspMain != null)
                                        mspMain.stopTimer();
                                    this.reassemplyCache.remove(msp);
                                }
                                if (sgmMsgFst.getRemainingSegments() != 1)
                                    return;

                                sgmMsgFst.setReceivedNextSegment(sgmMsg);
                                msg = sgmMsgFst;
                            } else {
                                // not last segment
                                sgmMsgFst.setReceivedNextSegment(sgmMsg);
                                return;
                            }
                        }
                    }
                }
            }

            if (msg instanceof SccpAddressedMessageImpl) {
                // CR or connectionless messages
                SccpAddressedMessageImpl msgAddr = (SccpAddressedMessageImpl) msg;

                // adding OPC into CallingPartyAddress if it is absent there and
                // "RouteOnSsn"
                SccpAddress addr = msgAddr.getCallingPartyAddress();
                if (addr != null
                        && addr.getAddressIndicator().getRoutingIndicator() == RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN) {
                    if (!addr.getAddressIndicator().isPCPresent()) {
                        msgAddr.setCallingPartyAddress(new SccpAddressImpl(RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN, null, msgAddr.getIncomingOpc(), addr
                                .getSubsystemNumber()));
                    }
                }

                sccpRoutingControl.routeMssgFromMtp(msgAddr);

            } else if (msg instanceof SccpConnMessage) {
                // non-addressed message processing (these are connected-oriented messages in the connected phase)
                sccpRoutingControl.routeMssgFromMtpConn((SccpConnMessage) msg);

            } else {
                logger.warn(String
                        .format("Rx SCCP message which is not instance of SccpAddressedMessage or SccpSegmentableMessage" +
                                " and doesn't implement SccpConnMessage. Will be dropped. Message=", msg));
            }
        } catch (Exception e) {
            logger.error("IOException while handling SCCP message: " + e.getMessage(), e);
        }
    }

    public class MessageReassemblyProcess implements Runnable {
        private int segmentationLocalRef;
        private SccpAddress callingPartyAddress;

        private Future timer;

        public MessageReassemblyProcess(int segmentationLocalRef, SccpAddress callingPartyAddress) {
            this.segmentationLocalRef = segmentationLocalRef;
            this.callingPartyAddress = callingPartyAddress;
        }

        @Override
        public boolean equals(Object obj) {
            if (obj == null)
                return false;
            if (!(obj instanceof MessageReassemblyProcess))
                return false;
            MessageReassemblyProcess x = (MessageReassemblyProcess) obj;
            if (this.segmentationLocalRef != x.segmentationLocalRef)
                return false;

            if (this.callingPartyAddress == null || x.callingPartyAddress == null)
                return false;

            return this.callingPartyAddress.equals(x.callingPartyAddress);
        }

        @Override
        public int hashCode() {
            return this.segmentationLocalRef;
        }

        public void startTimer() {
            this.timer = timerExecutors.schedule(this, reassemblyTimerDelay, TimeUnit.MILLISECONDS);
        }

        public void stopTimer() {
            if (this.timer != null) {
                this.timer.cancel(false);
                this.timer = null;
            }
        }

        public void run() {
            SccpSegmentableMessageImpl msg = null;
            synchronized (reassemplyCache) {
                msg = reassemplyCache.remove(this);
                if (msg == null)
                    return;

                msg.cancelSegmentation();
            }

            try {
                sccpRoutingControl.sendSccpError(msg, ReturnCauseValue.CANNOT_REASEMBLE, null);
            } catch (Exception e) {
                logger.warn("IOException when sending an error message", e);
            }
        }
    }

    /**
     * Persist
     */
    public void store() {

        // TODO : Should we keep reference to Objects rather than recreating
        // everytime?
        try {
            XMLObjectWriter writer = XMLObjectWriter.newInstance(new FileOutputStream(persistFile.toString()));
            writer.setBinding(binding);
            // Enables cross-references.
            // writer.setReferenceResolver(new XMLReferenceResolver());
            writer.setIndentation(TAB_INDENT);

            writer.write(this.zMarginXudtMessage, Z_MARGIN_UDT_MSG, Integer.class);

            writer.write(this.connEstTimerDelay, CONN_EST_TIMER_DELAY, Integer.class);
            writer.write(this.iasTimerDelay, IAS_TIMER_DELAY, Integer.class);
            writer.write(this.iarTimerDelay, IAR_TIMER_DELAY, Integer.class);
            writer.write(this.relTimerDelay, REL_TIMER_DELAY, Integer.class);
            writer.write(this.repeatRelTimerDelay, REPEAT_REL_TIMER_DELAY, Integer.class);
            writer.write(this.intTimerDelay, INT_TIMER_DELAY, Integer.class);
            writer.write(this.guardTimerDelay, GUARD_TIMER_DELAY, Integer.class);
            writer.write(this.resetTimerDelay, RESET_TIMER_DELAY, Integer.class);
            writer.write(this.reassemblyTimerDelay, REASSEMBLY_TIMER_DELAY, Integer.class);

            writer.write(this.maxDataMessage, MAX_DATA_MSG, Integer.class);
            writer.write(this.periodOfLogging, PERIOD_OF_LOG, Integer.class);
            writer.write(this.removeSpc, REMOVE_SPC, Boolean.class);
            writer.write(this.respectPc, RESPECT_PC, Boolean.class);
            writer.write(this.canRelay, CAN_RELAY, Boolean.class);
            writer.write(this.timerExecutorsThreadCount, TIMER_EXECUTORS_THREAD_COUNT, Integer.class);
            writer.write(this.previewMode, PREVIEW_MODE, Boolean.class);
            if (this.sccpProtocolVersion != null)
                writer.write(this.sccpProtocolVersion.toString(), SCCP_PROTOCOL_VERSION, String.class);

            writer.write(this.congControl_TIMER_A, CONG_CONTROL_TIMER_A, Integer.class);
            writer.write(this.congControl_TIMER_D, CONG_CONTROL_TIMER_D, Integer.class);
            if (this.congControl_Algo != null)
                writer.write(this.congControl_Algo.toString(), CONG_CONTROL_ALGO, String.class);
            writer.write(this.congControl_blockingOutgoungSccpMessages, CONG_CONTROL_BLOCKING_OUTGOUNG_SCCP_MESSAGES,
                    Boolean.class);

            writer.write(this.sstTimerDuration_Min, SST_TIMER_DURATION_MIN, Integer.class);
            writer.write(this.sstTimerDuration_Max, SST_TIMER_DURATION_MAX, Integer.class);
            writer.write(this.sstTimerDuration_IncreaseFactor, SST_TIMER_DURATION_INCREASE_FACTOR, Double.class);

            writer.close();
        } catch (Exception e) {
            this.logger.error(
                    String.format("Error while persisting the Sccp Resource state in file=%s", persistFile.toString()), e);
        }
    }

    /**
     * Load and create LinkSets and Link from persisted file
     *
     * @throws Exception
     */
    protected void load() throws FileNotFoundException {
        XMLObjectReader reader = null;
        try {
            reader = XMLObjectReader.newInstance(new FileInputStream(persistFile.toString()));

            reader.setBinding(binding);
            load(reader);
        } catch (XMLStreamException ex) {
            // this.logger.info(
            // "Error while re-creating Linksets from persisted file", ex);
        }
    }

    protected void load(XMLObjectReader reader) throws XMLStreamException {

       Integer vali = reader.read(Z_MARGIN_UDT_MSG, Integer.class);
            if (vali != null)
                this.zMarginXudtMessage = vali;

            vali = reader.read(CONN_EST_TIMER_DELAY, Integer.class);
            if (vali != null)
                this.connEstTimerDelay = vali;
            vali = reader.read(IAS_TIMER_DELAY, Integer.class);
            if (vali != null)
                this.iasTimerDelay = vali;
            vali = reader.read(IAR_TIMER_DELAY, Integer.class);
            if (vali != null)
                this.iarTimerDelay = vali;
            vali = reader.read(REL_TIMER_DELAY, Integer.class);
            if (vali != null)
                this.relTimerDelay = vali;
            vali = reader.read(REPEAT_REL_TIMER_DELAY, Integer.class);
            if (vali != null)
                this.repeatRelTimerDelay = vali;
            vali = reader.read(INT_TIMER_DELAY, Integer.class);
            if (vali != null)
                this.intTimerDelay = vali;
            vali = reader.read(GUARD_TIMER_DELAY, Integer.class);
            if (vali != null)
                this.guardTimerDelay = vali;
            vali = reader.read(RESET_TIMER_DELAY, Integer.class);
            if (vali != null)
                this.resetTimerDelay = vali;
            vali = reader.read(REASSEMBLY_TIMER_DELAY, Integer.class);
            if (vali != null)
                this.reassemblyTimerDelay = vali;

            vali = reader.read(MAX_DATA_MSG, Integer.class);
            if (vali != null)
                this.maxDataMessage = vali;
            vali = reader.read(PERIOD_OF_LOG, Integer.class);
            if (vali != null)
                this.periodOfLogging = vali;

            Boolean volb = reader.read(REMOVE_SPC, Boolean.class);
            if (volb != null)
                this.removeSpc = volb;

            volb = reader.read(RESPECT_PC, Boolean.class);
            if (volb != null)
                this.respectPc = volb;

            volb = reader.read(CAN_RELAY, Boolean.class);
            if (volb != null)
                this.canRelay = volb;

            vali = reader.read(TIMER_EXECUTORS_THREAD_COUNT, Integer.class);
            if (vali != null)
                this.timerExecutorsThreadCount = vali;

            volb = reader.read(PREVIEW_MODE, Boolean.class);
            if (volb != null)
                this.previewMode = volb;
            volb = reader.read(RESERVED_FOR_NATIONAL_USE_VALUE_ADDRESS_INDICATOR, Boolean.class);

            String s1 = reader.read(SCCP_PROTOCOL_VERSION, String.class);
            if (s1 != null)
                this.sccpProtocolVersion = Enum.valueOf(SccpProtocolVersion.class, s1);

            vali = reader.read(CONG_CONTROL_TIMER_A, Integer.class);
            if (vali != null)
                this.congControl_TIMER_A = vali;
            vali = reader.read(CONG_CONTROL_TIMER_D, Integer.class);
            if (vali != null)
                this.congControl_TIMER_D = vali;
            s1 = reader.read(CONG_CONTROL_ALGO, String.class);
            if (s1 != null)
                this.congControl_Algo = Enum.valueOf(SccpCongestionControlAlgo.class, s1);
            volb = reader.read(CONG_CONTROL_BLOCKING_OUTGOUNG_SCCP_MESSAGES, Boolean.class);
            if (volb != null)
                this.congControl_blockingOutgoungSccpMessages = volb;

            vali = reader.read(SST_TIMER_DURATION_MIN, Integer.class);
            if (vali != null)
                this.sstTimerDuration_Min = vali;
            vali = reader.read(SST_TIMER_DURATION_MAX, Integer.class);
            if (vali != null)
                this.sstTimerDuration_Max = vali;
            Double vald = reader.read(SST_TIMER_DURATION_INCREASE_FACTOR, Double.class);
            if (vald != null)
                this.sstTimerDuration_IncreaseFactor = vald;

            reader.close();

    }
}
