/*
 * JBoss, Home of Professional Open Source
 * Copyright 2011, Red Hat, Inc. and individual contributors
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

package org.restcomm.ss7.management.transceiver;

import static org.testng.Assert.assertEquals;

import java.io.IOException;
import java.nio.ByteBuffer;

import org.restcomm.ss7.management.transceiver.Message;
import org.restcomm.ss7.management.transceiver.MessageFactory;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

/**
 *
 * @author amit bhayani
 *
 */
public class MessageFactoryTest {

    private MessageFactory messageFactory = null;

    public MessageFactoryTest() {
    }

    @BeforeClass
    public static void setUpClass() throws Exception {
    }

    @AfterClass
    public static void tearDownClass() throws Exception {
    }

    @BeforeTest
    public void setUp() {
        messageFactory = new MessageFactory();
    }

    @AfterTest
    public void tearDown() {
    }

    @Test
    public void testEmptyMessage() throws IOException {
        Message msgInput = messageFactory.createMessage("");

        ByteBuffer rxBuffer = ByteBuffer.allocateDirect(8192);
        msgInput.encode(rxBuffer);
        rxBuffer.flip();

        Message messageOutpu = messageFactory.createMessage(rxBuffer);

        assertEquals(messageOutpu, msgInput);
    }

    @Test
    public void testLongMessage() throws IOException {

        String message = new StringBuffer()
                .append("linkset1      dahdi    opc=1           apc=2           ni=3    state=UNAVAILABLE\n")
                .append("    link1       span=1   channelId=1   code=1  state=UNAVAILABLE\n")
                .append("    link2       span=2   channelId=2   code=3  state=UNAVAILABLE\n").append("\n")
                .append("linkset2      dahdi    opc=123         apc=45678       ni=3    state=UNAVAILABLE\n").toString();
        byte[] data = { 0x00, 0x00, 0x01, 0x2a, 0x6c, 0x69, 0x6e, 0x6b, 0x73, 0x65, 0x74, 0x31, 0x20, 0x20, 0x20, 0x20, 0x20,
                0x20, 0x64, 0x61, 0x68, 0x64, 0x69, 0x20, 0x20, 0x20, 0x20, 0x6f, 0x70, 0x63, 0x3d, 0x31, 0x20, 0x20, 0x20,
                0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x61, 0x70, 0x63, 0x3d, 0x32, 0x20, 0x20, 0x20, 0x20, 0x20,
                0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x6e, 0x69, 0x3d, 0x33, 0x20, 0x20, 0x20, 0x20, 0x73, 0x74, 0x61, 0x74,
                0x65, 0x3d, 0x55, 0x4e, 0x41, 0x56, 0x41, 0x49, 0x4c, 0x41, 0x42, 0x4c, 0x45, 0x0a, 0x20, 0x20, 0x20, 0x20,
                0x6c, 0x69, 0x6e, 0x6b, 0x31, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x73, 0x70, 0x61, 0x6e, 0x3d, 0x31,
                0x20, 0x20, 0x20, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x49, 0x64, 0x3d, 0x31, 0x20, 0x20, 0x20, 0x63,
                0x6f, 0x64, 0x65, 0x3d, 0x31, 0x20, 0x20, 0x73, 0x74, 0x61, 0x74, 0x65, 0x3d, 0x55, 0x4e, 0x41, 0x56, 0x41,
                0x49, 0x4c, 0x41, 0x42, 0x4c, 0x45, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x6c, 0x69, 0x6e, 0x6b, 0x32, 0x20, 0x20,
                0x20, 0x20, 0x20, 0x20, 0x20, 0x73, 0x70, 0x61, 0x6e, 0x3d, 0x32, 0x20, 0x20, 0x20, 0x63, 0x68, 0x61, 0x6e,
                0x6e, 0x65, 0x6c, 0x49, 0x64, 0x3d, 0x32, 0x20, 0x20, 0x20, 0x63, 0x6f, 0x64, 0x65, 0x3d, 0x33, 0x20, 0x20,
                0x73, 0x74, 0x61, 0x74, 0x65, 0x3d, 0x55, 0x4e, 0x41, 0x56, 0x41, 0x49, 0x4c, 0x41, 0x42, 0x4c, 0x45, 0x0a,
                0x0a, 0x6c, 0x69, 0x6e, 0x6b, 0x73, 0x65, 0x74, 0x32, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x64, 0x61, 0x68,
                0x64, 0x69, 0x20, 0x20, 0x20, 0x20, 0x6f, 0x70, 0x63, 0x3d, 0x31, 0x32, 0x33, 0x20, 0x20, 0x20, 0x20, 0x20,
                0x20, 0x20, 0x20, 0x20, 0x61, 0x70, 0x63, 0x3d, 0x34, 0x35, 0x36, 0x37, 0x38, 0x20, 0x20, 0x20, 0x20, 0x20,
                0x20, 0x20, 0x6e, 0x69, 0x3d, 0x33, 0x20, 0x20, 0x20, 0x20, 0x73, 0x74, 0x61, 0x74, 0x65, 0x3d, 0x55, 0x4e,
                0x41, 0x56, 0x41, 0x49, 0x4c, 0x41, 0x42, 0x4c, 0x45, 0x0a, 0x0a };

        ByteBuffer buffer = ByteBuffer.wrap(data);

        Message msg = messageFactory.createMessage(buffer);

        // 4 bytes are for length
        for (int i = 0; i < msg.data.length; i++) {
            assertEquals(data[4 + i], msg.data[i]);
        }

    }

    public static final String dump(ByteBuffer buff, int size, boolean asBits) {
        String s = "";
        buff.rewind();

        while (buff.position() < size) {
            String ss = null;
            if (!asBits) {
                ss = Integer.toHexString(buff.get() & 0xff);
            } else {
                ss = Integer.toBinaryString(buff.get() & 0xff);
            }
            ss = fillInZeroPrefix(ss, asBits);
            s += " " + ss;
        }
        return s;
    }

    public static final String fillInZeroPrefix(String ss, boolean asBits) {
        if (asBits) {
            if (ss.length() < 8) {
                for (int j = ss.length(); j < 8; j++) {
                    ss = "0" + ss;
                }
            }
        } else {
            // hex
            if (ss.length() < 2) {

                ss = "0" + ss;
            }
        }

        return ss;
    }
}
