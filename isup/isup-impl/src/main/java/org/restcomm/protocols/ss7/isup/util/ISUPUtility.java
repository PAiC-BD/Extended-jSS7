/*
 * TeleStax, Open Source Cloud Communications
 * Copyright 2012, Telestax Inc and individual contributors
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

/**
 * Start time:16:56:29 2009-07-17<br>
 * Project: mobicents-isup-stack<br>
 *
 * @author <a href="mailto:baranowb@gmail.com">Bartosz Baranowski </a>
 *
 */
package org.restcomm.protocols.ss7.isup.util;

import org.restcomm.protocols.ss7.isup.impl.message.ISUPMessageFactoryImpl;
import org.restcomm.protocols.ss7.isup.impl.message.parameter.ISUPParameterFactoryImpl;

/**
 * Start time:16:56:29 2009-07-17<br>
 * Project: mobicents-isup-stack<br>
 * Small class with some utility methods to work on raw without stack.
 *
 * @author <a href="mailto:baranowb@gmail.com"> Bartosz Baranowski </a>
 */
public class ISUPUtility {

    private static final ISUPParameterFactoryImpl parameterFactory = new ISUPParameterFactoryImpl();
    private static final ISUPMessageFactoryImpl messageFactory = new ISUPMessageFactoryImpl(parameterFactory);

    public static String toHex(byte[] b) {

        String out = "";

        for (int index = 0; index < b.length; index++) {

            out += "b[" + index + "][" + Integer.toHexString(b[index]) + "]\n";

            // out+="\n";
        }

        return out;

    }
    //
    // /**
    // * Offset where ISUP data should start in MSU
    // */
    // public static final int MSU_SHIFT = 5;
    // /**
    // * Offset where ISUP parameters should start in MSU
    // */
    // public static final int ISUP_SHIFT = MSU_SHIFT + 3;
    //
    // public static void setCIC(byte[] msu, int cic) {
    // msu[MSU_SHIFT] = (byte) cic;
    // msu[MSU_SHIFT + 1] = (byte) ((cic >> 8) & 0x0F);
    // }
    //
    // public static int getCIC(byte[] msu) {
    // int cic = (msu[MSU_SHIFT] & 0xFF);
    // cic |= ((msu[MSU_SHIFT + 1] & 0x0F) << 8);
    // return cic;
    // }
    //
    // public static void setMessageCode(byte[] msu, int code) {
    // msu[MSU_SHIFT + 2] = (byte) code;
    // }
    //
    // public static int getMessageCode(byte[] msu) {
    // return msu[MSU_SHIFT + 2] & 0xFF;
    // }
    //
    // private static byte[] getRawMessage(byte[] msu) throws IOException {
    // ByteArrayInputStream bis = new ByteArrayInputStream(msu);
    // bis.skip(MSU_SHIFT);
    // byte[] b = new byte[bis.available()];
    // bis.read(b);
    // return b;
    // }
    //
    // public static CircuitGroupBlockingMessage getCircuitGroupBlocking(byte[] msu) throws ParameterException, IOException {
    // byte[] b = getRawMessage(msu);
    // int cic = getCIC(msu);
    // CircuitGroupBlockingMessage msg = messageFactory.createCGB(cic);
    // msg.decode(b);
    // return msg;
    // }
    //
    // public static CircuitGroupBlockingAckMessage getCircuitGroupBlockingAck(byte[] msu) throws ParameterException,
    // IOException {
    // byte[] b = getRawMessage(msu);
    // CircuitGroupBlockingAckMessage msg = messageFactory.createCGBA();
    // msg.decode(b);
    // return msg;
    // }
    //
    // public static CircuitGroupUnblockingMessage getCircuitGroupUnBlocking(byte[] msu) throws ParameterException, IOException
    // {
    // byte[] b = getRawMessage(msu);
    // int cic = getCIC(msu);
    // CircuitGroupUnblockingMessage msg = messageFactory.createCGU(cic);
    // msg.decode(b);
    // return msg;
    // }
    //
    // public static CircuitGroupUnblockingAckMessage getCircuitGroupUnBlockingAck(byte[] msu) throws ParameterException,
    // IOException {
    // byte[] b = getRawMessage(msu);
    // CircuitGroupUnblockingAckMessage msg = messageFactory.createCGUA();
    // msg.decode(b);
    // return msg;
    // }
    //
    // public static CircuitGroupResetMessage getCircuitGroupResetMessage(byte[] msu) throws ParameterException, IOException {
    // byte[] b = getRawMessage(msu);
    // int cic = getCIC(msu);
    // CircuitGroupResetMessage msg = messageFactory.createGRS(cic);
    // msg.decode(b);
    // return msg;
    // }
    //
    // public static CircuitGroupResetAckMessage getCircuitGroupResetAckMessage(byte[] msu) throws ParameterException,
    // IOException {
    // byte[] b = getRawMessage(msu);
    // CircuitGroupResetAckMessage msg = messageFactory.createGRA();
    // msg.decode(b);
    // return msg;
    // }
    //
    // private static final byte[] EMPTY = new byte[MSU_SHIFT];
    //
    // /**
    // * Encodes message to MSU format, first bytes should be over writen with
    // * back routing label.
    // *
    // * @param msg
    // * @return
    // * @throws IOException
    // */
    // public static byte[] encodeToMsuFormat(ISUPMessage msg) throws IOException {
    // ByteArrayOutputStream bos = new ByteArrayOutputStream();
    // bos.write(EMPTY);
    // msg.encode(bos);
    // return bos.toByteArray();
    // }

}
