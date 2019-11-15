
package org.restcomm.protocols.ss7.sniffer.impl;
import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;

import org.apache.log4j.Logger;
import org.restcomm.protocols.ss7.m3ua.As;
import org.restcomm.protocols.ss7.m3ua.Asp;
import org.restcomm.protocols.ss7.m3ua.AspFactory;
import org.restcomm.protocols.ss7.m3ua.M3UACounterProvider;
import org.restcomm.protocols.ss7.m3ua.M3UAManagementEventListener;
import org.restcomm.protocols.ss7.m3ua.State;
import org.restcomm.protocols.ss7.m3ua.impl.M3UAManagementImpl;
import org.restcomm.protocols.ss7.mtp.Mtp3EndCongestionPrimitive;
import org.restcomm.protocols.ss7.mtp.Mtp3PausePrimitive;
import org.restcomm.protocols.ss7.mtp.Mtp3ResumePrimitive;
import org.restcomm.protocols.ss7.mtp.Mtp3StatusPrimitive;
import org.restcomm.protocols.ss7.mtp.Mtp3TransferPrimitive;
import org.restcomm.protocols.ss7.mtp.Mtp3UserPartListener;
import org.mobicents.protocols.api.Association;
import org.mobicents.protocols.api.Management;
import org.mobicents.protocols.api.ManagementEventListener;
import org.mobicents.protocols.api.Server;
import org.restcomm.protocols.ss7.statistics.api.LongValue;

public class SnifferImpl implements M3UAManagementEventListener, Mtp3UserPartListener, ManagementEventListener {
        private M3UAManagementImpl m3uaMgmt;
        private M3UACounterProvider cprovider;
        private Management sctpMgmt;
        public String running_flag;
        public String endpoint;
        public String job;
        public String kubernetes_name;
        public String kubernetes_namespace;
        public String kubernetes_pod_name;
        public String instance;
        public String log_file="/monitor.log";
        public Logger logger = Logger.getLogger(SnifferImpl.class);
        public long m3uain = 0;
        public long m3uaout = 0;
        public long mtp3Bytes = 0;
        public boolean custom = false;

        public SnifferImpl(M3UAManagementImpl m3uaMgmt, Management sctpMgmt, String running_flag) throws FileNotFoundException  {

                this.m3uaMgmt = m3uaMgmt;
                this.sctpMgmt = sctpMgmt;
                this.running_flag = running_flag;
                log_file = System.getProperty("jboss.server.log.dir") + log_file;
                m3uaMgmt.addM3UAManagementEventListener(this);
                m3uaMgmt.addMtp3UserPartListener(this);
                sctpMgmt.addManagementEventListener(this);
        }

        public SnifferImpl(M3UAManagementImpl m3uaMgmt, Management sctpMgmt, String running_flag, String endpoint, String job, String kubernetes_name, String kubernetes_namespace, String kubernetes_pod_name) throws FileNotFoundException  {

                this.custom = true;
                this.m3uaMgmt = m3uaMgmt;
                this.sctpMgmt = sctpMgmt;
                this.running_flag = running_flag;
                this.endpoint = endpoint;
                this.job = job;
                this.kubernetes_name = kubernetes_name;
                this.kubernetes_namespace = kubernetes_namespace;
                this.kubernetes_pod_name = kubernetes_pod_name;
                this.instance = System.getProperty("jboss.bind.address");
                log_file = System.getProperty("jboss.server.log.dir") + log_file;
                m3uaMgmt.addM3UAManagementEventListener(this);
                m3uaMgmt.addMtp3UserPartListener(this);
                sctpMgmt.addManagementEventListener(this);
        }

        public void start() throws IllegalStateException {
                if(running_flag.equals("true")){

                        logger.info("starting Sniffer ...");

                        try {
                                this.m3uaMgmt.setStatisticsEnabled(true);
                        } catch (Exception e) {
                                logger.error("Cannot enable stats! "+e.getMessage());
                        }
                        cprovider = m3uaMgmt.getCounterProviderImpl();

                        new Timer().scheduleAtFixedRate( new Task( cprovider, m3uaMgmt, sctpMgmt, log_file), 5000, 5000);
                }
                else{
                        logger.info("Sniffer is not activated.");
                }
        }


        class Task extends TimerTask {

                private M3UACounterProvider cprovider;
                private M3UAManagementImpl m3uaMgmt;
                private Management sctpMgmt;
                private String log_file;
                private HashMap<String, Integer> ASPmonitorList = new HashMap<String, Integer>();
                public Task(M3UACounterProvider cprovider, M3UAManagementImpl m3uaMgmt, Management sctpMgmt, String log_file){
                        this.cprovider = cprovider;
                        this.m3uaMgmt = m3uaMgmt;
                        this.sctpMgmt = sctpMgmt;
                        this.log_file = log_file;
                }

                @Override
                public void run() {
                        Logger logger = Logger.getLogger(SnifferImpl.class);
                        double asgauge = 0.0;
                        double aspgauge = 0.0;
                        double sctpgauge = 0.0;
                        String sctpstatus = "";
                        String log = "";
                        FileWriter fw;
                        BufferedWriter bw;
                        log = log + "# TYPE restcomm_sctp_association gauge\n";
                        if(!(sctpMgmt.getAssociations().isEmpty())){
                                Map<String, Association> assocs = sctpMgmt.getAssociations();
                                for(Map.Entry<String, Association> entry: assocs.entrySet()){
                                        //we need to generate 2 lines (for each possible status: UP, DOWN) since for prometheus to count and monitor each state
                                        try {
                                                if(sctpMgmt.getAssociation(entry.getKey()).isUp()){
                                                        sctpgauge = 1.0;
                                                        sctpstatus = "UP";
                                                        log = log +"sctp_association{name=\"" + sctpMgmt.getAssociation(entry.getKey()).getName() + "\",host_address=\""+ sctpMgmt.getAssociation(entry.getKey()).getHostAddress() +"\",host_port=\""+ sctpMgmt.getAssociation(entry.getKey()).getHostPort() +"\",association_type=\""+ sctpMgmt.getAssociation(entry.getKey()).getAssociationType() + "\",peer_address=\""+ sctpMgmt.getAssociation(entry.getKey()).getPeerAddress() + "\",status=\"UP\",ip_channel_type=\""+ sctpMgmt.getAssociation(entry.getKey()).getAssociationType() +"\",peer_port=\""+ sctpMgmt.getAssociation(entry.getKey()).getPeerPort() +"\"} "+sctpgauge +"\n";
                                                        log = log +"sctp_association{name=\"" + sctpMgmt.getAssociation(entry.getKey()).getName() + "\",host_address=\""+ sctpMgmt.getAssociation(entry.getKey()).getHostAddress() +"\",host_port=\""+ sctpMgmt.getAssociation(entry.getKey()).getHostPort() +"\",association_type=\""+ sctpMgmt.getAssociation(entry.getKey()).getAssociationType() + "\",peer_address=\""+ sctpMgmt.getAssociation(entry.getKey()).getPeerAddress() + "\",status=\"DOWN\",ip_channel_type=\""+ sctpMgmt.getAssociation(entry.getKey()).getAssociationType() +"\",peer_port=\""+ sctpMgmt.getAssociation(entry.getKey()).getPeerPort() +"\"} "+ (sctpgauge - 1.0)+"\n";
                                                }
                                                else{
                                                        sctpgauge = 1.0;
                                                        log = log +"sctp_association{name=\"" + sctpMgmt.getAssociation(entry.getKey()).getName() + "\",host_address=\""+ sctpMgmt.getAssociation(entry.getKey()).getHostAddress() +"\",host_port=\""+ sctpMgmt.getAssociation(entry.getKey()).getHostPort() +"\",association_type=\""+ sctpMgmt.getAssociation(entry.getKey()).getAssociationType() + "\",peer_address=\""+ sctpMgmt.getAssociation(entry.getKey()).getPeerAddress() + "\",status=\"DOWN\",ip_channel_type=\""+ sctpMgmt.getAssociation(entry.getKey()).getAssociationType() +"\",peer_port=\""+ sctpMgmt.getAssociation(entry.getKey()).getPeerPort() +"\"} "+sctpgauge+"\n";
                                                        log = log +"sctp_association{name=\"" + sctpMgmt.getAssociation(entry.getKey()).getName() + "\",host_address=\""+ sctpMgmt.getAssociation(entry.getKey()).getHostAddress() +"\",host_port=\""+ sctpMgmt.getAssociation(entry.getKey()).getHostPort() +"\",association_type=\""+ sctpMgmt.getAssociation(entry.getKey()).getAssociationType() + "\",peer_address=\""+ sctpMgmt.getAssociation(entry.getKey()).getPeerAddress() + "\",status=\"UP\",ip_channel_type=\""+ sctpMgmt.getAssociation(entry.getKey()).getAssociationType() +"\",peer_port=\""+ sctpMgmt.getAssociation(entry.getKey()).getPeerPort() +"\"} "+ (sctpgauge - 1.0)+"\n";
                                                }
                                        } catch (Exception e) {
                                                // TODO Auto-generated catch block
                                                e.printStackTrace();
                                        }
                                }
                        }
                        //log = log +sctpMgmt.getPersistDir());
                        Iterator<As> iterator = m3uaMgmt.getAppServers().iterator();
                        log = log +"# TYPE restcomm_m3ua_as gauge"+"\n";
                        while(iterator.hasNext()){
                                //we need to generate 4 lines (for each possible status: DOWN, PENDING, INACTIVE, ACTIVE) since for prometheus to count and monitor each state

                                As as = (As) iterator.next();
                                if(as.getState().toString().equals("ACTIVE")) {
                                        asgauge = 1.0;
                                        log = log +"restcomm_m3ua_as{name=\""+as.getName()+"\",status=\"ACTIVE\"} "+asgauge+"\n";
                                        log = log +"restcomm_m3ua_as{name=\""+as.getName()+"\",status=\"DOWN\"} "+ (asgauge - 1.0)+"\n";
                                        log = log +"restcomm_m3ua_as{name=\""+as.getName()+"\",status=\"PENDING\"} "+ (asgauge - 1.0)+"\n";
                                        log = log +"restcomm_m3ua_as{name=\""+as.getName()+"\",status=\"INACTIVE\"} "+ (asgauge - 1.0)+"\n";
                                }
                                else if(as.getState().toString().equals("DOWN")){
                                        asgauge = 1.0;
                                        log = log +"restcomm_m3ua_as{name=\""+as.getName()+"\",status=\"DOWN\"} "+asgauge+"\n";
                                        log = log +"restcomm_m3ua_as{name=\""+as.getName()+"\",status=\"ACTIVE\"} "+ (asgauge - 1.0)+"\n";
                                        log = log +"restcomm_m3ua_as{name=\""+as.getName()+"\",status=\"PENDING\"} "+ (asgauge - 1.0)+"\n";
                                        log = log +"restcomm_m3ua_as{name=\""+as.getName()+"\",status=\"INACTIVE\"} "+ (asgauge - 1.0)+"\n";
                                }
                                else if(as.getState().toString().equals("PENDING")){
                                        asgauge = 1.0;
                                        log = log +"restcomm_m3ua_as{name=\""+as.getName()+"\",status=\"PENDING\"} "+asgauge+"\n";
                                        log = log +"restcomm_m3ua_as{name=\""+as.getName()+"\",status=\"ACTIVE\"} "+ (asgauge - 1.0)+"\n";
                                        log = log +"restcomm_m3ua_as{name=\""+as.getName()+"\",status=\"DOWN\"} "+ (asgauge - 1.0)+"\n";
                                        log = log +"restcomm_m3ua_as{name=\""+as.getName()+"\",status=\"INACTIVE\"} "+ (asgauge - 1.0)+"\n";
                                }
                                else if(as.getState().toString().equals("INACTIVE")){
                                        asgauge = 1.0;
                                        log = log +"restcomm_m3ua_as{name=\""+as.getName()+"\",status=\"INACTIVE\"} "+asgauge+"\n";
                                        log = log +"restcomm_m3ua_as{name=\""+as.getName()+"\",status=\"ACTIVE\"} "+ (asgauge - 1.0)+"\n";
                                        log = log +"restcomm_m3ua_as{name=\""+as.getName()+"\",status=\"DOWN\"} "+ (asgauge - 1.0)+"\n";
                                        log = log +"restcomm_m3ua_as{name=\""+as.getName()+"\",status=\"PENDING\"} "+ (asgauge - 1.0)+"\n";
                                }
                        }
                        log = log +"# TYPE restcomm_m3ua_asp gauge"+"\n";

                        Iterator<AspFactory> iteratoraspf =  m3uaMgmt.getAspfactories().iterator();
                        while(iteratoraspf.hasNext()){
                                AspFactory aspf = (AspFactory) iteratoraspf.next();
                                Iterator<Asp> iteratorasp = aspf.getAspList().iterator();
                                String asp_assocname = aspf.getAssociation().getName();

                                while(iteratorasp.hasNext()){
                                        //we need to generate 3 lines (for each possible status: DOWN, INACTIVE, ACTIVE) since for prometheus to count and monitor each state
                                        Asp asp = (Asp) iteratorasp.next();
                                        As linked_as = asp.getAs();
                                        if(asp.getState().toString().equals("ACTIVE")){
                                                aspgauge = 1.0;
                                                log = log +"restcomm_m3ua_asp{name=\""+asp.getName()+"\",status=\"ACTIVE\"} "+aspgauge+"\n";
                                                log = log +"restcomm_m3ua_asp{name=\""+asp.getName()+"\",status=\"INACTIVE\"} "+ (aspgauge - 1.0)+"\n";
                                                log = log +"restcomm_m3ua_asp{name=\""+asp.getName()+"\",status=\"DOWN\"} "+ (aspgauge - 1.0)+"\n";
                                        }
                                        else if(asp.getState().toString().equals("INACTIVE")){
                                                aspgauge = 1.0;
                                                log = log +"restcomm_m3ua_asp{name=\""+asp.getName()+"\",status=\"INACTIVE\"} "+aspgauge+"\n";
                                                log = log +"restcomm_m3ua_asp{name=\""+asp.getName()+"\",status=\"ACTIVE\"} "+ (aspgauge - 1.0)+"\n";
                                                log = log +"restcomm_m3ua_asp{name=\""+asp.getName()+"\",status=\"DOWN\"} "+ (aspgauge - 1.0)+"\n";
                                        }
                                        else if(asp.getState().toString().equals("DOWN")){
                                                aspgauge = 1.0;
                                                log = log +"restcomm_m3ua_asp{name=\""+asp.getName()+"\",status=\"DOWN\"} "+aspgauge+"\n";
                                                log = log +"restcomm_m3ua_asp{name=\""+asp.getName()+"\",status=\"ACTIVE\"} "+ (aspgauge - 1.0)+"\n";
                                                log = log +"restcomm_m3ua_asp{name=\""+asp.getName()+"\",status=\"INACTIVE\"} "+ (aspgauge - 1.0)+"\n";
                                       }
                                       if((!(asp.getState().toString().equals("ACTIVE"))) && linked_as.getState().toString().equals("ACTIVE")){
                                                //verify if the association is already on the list
                                                if(ASPmonitorList.get(asp_assocname.toString()) != null){
                                                        logger.info("ASP Auditor: ASP "+ asp.getName() + " not ACTIVE and AS " + linked_as.getName() + " is ACTIVE, auditor counter value = " + ASPmonitorList.get(asp_assocname.toString()));
                                                        if(ASPmonitorList.get(asp_assocname.toString()) == 5){
                                                                try {
                                                                        logger.info("Threshold reached, stopping SCTP association: " + asp_assocname.toString());
                                                                        sctpMgmt.stopAssociation(asp_assocname.toString());
                                                                        int counter = 0;
                                                                        counter = ASPmonitorList.get(asp_assocname.toString());
                                                                        counter = counter + 1;
                                                                        ASPmonitorList.put(asp_assocname.toString(), counter);
                                                                } catch (Exception e) {
                                                                        // TODO Auto-generated catch block
                                                                        e.printStackTrace();
                                                                        ASPmonitorList.put(asp_assocname.toString(), 3);
                                                                }
                                                        }
                                                        else if(ASPmonitorList.get(asp_assocname.toString()) == 6){
                                                                try {
                                                                        sctpMgmt.startAssociation(asp_assocname);
                                                                        ASPmonitorList.remove(asp_assocname);
                                                                } catch (Exception e) {
                                                                        // TODO Auto-generated catch block
                                                                        e.printStackTrace();
                                                                        ASPmonitorList.put(asp_assocname.toString(), 3);
                                                                }
                                                        }
                                                        else{
                                                                int counter = 0;
                                                                counter = ASPmonitorList.get(asp_assocname.toString());
                                                                counter = counter + 1;
                                                                ASPmonitorList.put(asp_assocname.toString(), counter);
                                                        }
                                                }
                                                else{
                                                        ASPmonitorList.put(asp_assocname, 1);
                                                }

                                        }
                                        else if(ASPmonitorList.get(asp_assocname.toString()) != null){
                                                if(ASPmonitorList.get(asp_assocname.toString()) == 6){
                                                       try {
                                                                sctpMgmt.startAssociation(asp_assocname);
                                                                ASPmonitorList.remove(asp_assocname);
                                                        } catch (Exception e) {
                                                                // TODO Auto-generated catch block
                                                                e.printStackTrace();
                                                                ASPmonitorList.put(asp_assocname.toString(), 3);
                                                        }
                                                }
                                        }
                                        else{
                                                if(ASPmonitorList.get(asp_assocname.toString()) != null)
                                                {
                                                        ASPmonitorList.remove(asp_assocname);
                                                }
                                        }

                                        //M3UA OUT Counters
                                        Map<String, LongValue> aspcounterout = cprovider.getPacketsPerAssTx(aspf.getAssociation().getName());
                                        if(aspcounterout !=null && aspcounterout.size()> 0 ){
                                               for(Map.Entry<String, LongValue> entry: aspcounterout.entrySet()){
                                                      if(entry.getValue().getValue() > 0){
                                                        m3uaout = m3uaout + entry.getValue().getValue();
                                                      }
                                               }
                                               //logger.debug("M3UA TX Message counter = " + m3uaout);

                                       }

                                       //M3UA IN Counter
                                       Map<String, LongValue> aspcounterin = cprovider.getPacketsPerAssRx(aspf.getAssociation().getName());
                                        if(aspcounterin !=null && aspcounterin.size()> 0 ){
                                               for(Map.Entry<String, LongValue> entry: aspcounterin.entrySet()){
                                                      if(entry.getValue().getValue() > 0){
                                                        m3uain = m3uain + entry.getValue().getValue();
                                                      }
                                               }
                                               //logger.debug("M3UA RX Message counter = " + m3uain);

                                       }
                                }
                        }
                        logger.debug("M3UA TX Message counter = " + m3uaout);
                        logger.debug("M3UA RX Message counter = " + m3uain);
                        logger.debug("MTP Payload bytes counter = " + mtp3Bytes);
                        log = log +"# TYPE restcomm_m3ua_traffic counter"+"\n";
                        if(!custom){
                                log = log +"restcomm_m3ua_message_total{component=\"m3ua-metrics\",type=\"transfer-in\"} "+m3uain+"\n";
                                log = log +"restcomm_m3ua_message_total{component=\"m3ua-metrics\",type=\"transfer-out\"} "+m3uaout+"\n";
                                log = log +"restcomm_m3ua_payload_total{component=\"m3ua-metrics\",type=\"transfer-bytes\"} "+mtp3Bytes+"\n";
                        }
                        try {
                                fw = new FileWriter(log_file,false);
                                //fw = new FileWriter("/root/jboss-5.1.0.GA/server/default/log/monitor.log");
                                bw = new BufferedWriter(fw);
                                bw.write(log);
                                bw.close();
                                fw.close();
                        } catch ( IOException e1) {
                                // TODO Auto-generated catch block
                                e1.printStackTrace();
                        }
                        m3uain = 0;
                        m3uaout = 0;
                        mtp3Bytes = 0;
                }
        }


        @Override
        public void onAsActive(As arg0, State arg1) {
                // TODO Auto-generated method stub

        }

        @Override
        public void onAsCreated(As arg0) {
                // TODO Auto-generated method stub

        }

        @Override
        public void onAsDestroyed(As arg0) {
                // TODO Auto-generated method stub

        }

        @Override
        public void onAsDown(As arg0, State arg1) {
                // TODO Auto-generated method stub

        }

        @Override
        public void onAsInactive(As arg0, State arg1) {
                // TODO Auto-generated method stub

        }

        @Override
        public void onAsPending(As arg0, State arg1) {
                // TODO Auto-generated method stub

        }

        @Override
        public void onAspActive(Asp arg0, State arg1) {
                // TODO Auto-generated method stub
        }

        @Override
        public void onAspAssignedToAs(As arg0, Asp arg1) {
                // TODO Auto-generated method stub

        }

        @Override
        public void onAspDown(Asp arg0, State arg1) {
                // TODO Auto-generated method stub

        }

        @Override
        public void onAspFactoryCreated(AspFactory arg0) {
                // TODO Auto-generated method stub

        }

        @Override
        public void onAspFactoryDestroyed(AspFactory arg0) {
                // TODO Auto-generated method stub

        }

        @Override
        public void onAspFactoryStarted(AspFactory arg0) {
                // TODO Auto-generated method stub

        }

        @Override
        public void onAspFactoryStopped(AspFactory arg0) {
                // TODO Auto-generated method stub

        }

        @Override
        public void onAspInactive(Asp arg0, State arg1) {
                // TODO Auto-generated method stub

        }

        @Override
        public void onAspUnassignedFromAs(As arg0, Asp arg1) {
                // TODO Auto-generated method stub

        }

        @Override
        public void onRemoveAllResources() {
                // TODO Auto-generated method stub

        }

        @Override
        public void onServiceStarted() {
                // TODO Auto-generated method stub

        }

        @Override
        public void onServiceStopped() {
                // TODO Auto-generated method stub

        }

        @Override
        public void onMtp3PauseMessage(Mtp3PausePrimitive arg0) {


        }

        @Override
        public void onMtp3ResumeMessage(Mtp3ResumePrimitive arg0) {


        }

        @Override
        public void onMtp3StatusMessage(Mtp3StatusPrimitive arg0) {


        }

        @Override
        public void onMtp3TransferMessage(Mtp3TransferPrimitive arg0) {
               String message = new String(arg0.toString());
               String[] parts = message.split(",");
               String[] msgLenParts = parts[3].split("=");
               logger.debug("MTP message arrived: "+ arg0.toString());
               mtp3Bytes = mtp3Bytes + Long.parseLong(msgLenParts[1]);

        }

        @Override
        public void onAssociationAdded(Association arg0) {
                // TODO Auto-generated method stub

        }

        @Override
        public void onAssociationDown(Association arg0) {
                // TODO Auto-generated method stub

        }

        @Override
        public void onAssociationModified(Association arg0) {
                // TODO Auto-generated method stub

        }

        @Override
        public void onAssociationRemoved(Association arg0) {
                // TODO Auto-generated method stub

        }

        @Override
        public void onAssociationStarted(Association arg0) {
                // TODO Auto-generated method stub

        }

        @Override
        public void onAssociationStopped(Association arg0) {
                // TODO Auto-generated method stub

        }

        @Override
        public void onAssociationUp(Association arg0) {
                // TODO Auto-generated method stub

        }

        @Override
        public void onServerAdded(Server arg0) {
                // TODO Auto-generated method stub

        }

        @Override
        public void onServerModified(Server arg0) {
                // TODO Auto-generated method stub

        }

        @Override
        public void onServerRemoved(Server arg0) {
                // TODO Auto-generated method stub

        }

        @Override
        public void onMtp3EndCongestionMessage(Mtp3EndCongestionPrimitive arg0) {


        }
}
