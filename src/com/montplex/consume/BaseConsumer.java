package com.montplex.consume;

import com.montplex.resp.Category;
import com.montplex.resp.CmdArgs;
import com.montplex.resp.MonitorAndReplay;
import com.montplex.resp.RESP;
import com.montplex.tools.TablePrinter;
import io.netty.buffer.Unpooled;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.TreeMap;

public abstract class BaseConsumer {
    private final RESP resp = new RESP();

    private long validRespDataCount;
    private long clientReceivedCount;
    private long readCmdCount;
    private long writeCmdCount;
    private long otherCmdCount;

    private final TreeMap<String, Long> countByCmd = new TreeMap<>();

    private static long lastPrintMillis = 0L;

    protected static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    protected String offsetFromTime;
    protected long offsetFromTimeMillis = -1L;

    public void setOffsetFromTime(String offsetFromTime) {
        this.offsetFromTime = offsetFromTime;
        if (offsetFromTime != null) {
            try {
                this.offsetFromTimeMillis = DATE_FORMAT.parse(offsetFromTime).getTime();
            } catch (ParseException e) {
                throw new RuntimeException(e);
            }
        }
    }

    protected long offsetSkippedCount = 0L;

    private void printCmdArgs(CmdArgs cmdArgs) {
        var sb = new StringBuilder();
        sb.append(cmdArgs.cmd());
        sb.append(" ");
        for (int i = 0; i < cmdArgs.args().length; i++) {
            sb.append(new String(cmdArgs.args()[i]));
            if (i < cmdArgs.args().length - 1) {
                sb.append(" ");
            }
        }
        sb.append("\n");
        System.out.print(sb);
    }

    public void printAny(long millis, Object any, Object[] array) {
        // print time every 10 seconds
        final int printInterval = 1000 * 10;
        if (lastPrintMillis == 0L) {
            lastPrintMillis = millis;
            System.out.println(DATE_FORMAT.format(new Date(millis)));
        } else if (millis - lastPrintMillis > printInterval) {
            lastPrintMillis = millis;
            System.out.println(DATE_FORMAT.format(new Date(millis)));
        }

        printAnyWithSpacePrefix(any, array, 0);
    }

    private long okCount = 0L;
    private long nullCount = 0L;

    private void printIgnoreSome(String prefix, String str, boolean isTopValue) {
        if (isTopValue && str.equals("OK")) {
            okCount++;
            return;
        } else if (isTopValue && str.equals("null")) {
            nullCount++;
            return;
        }

        System.out.print(prefix);
        System.out.println(str);
    }

    private void printAnyWithSpacePrefix(Object any, Object[] array, int trim) {
        var prefix = " ".repeat(trim);
        if (any != null) {
            String str;
            if (any instanceof byte[] bytes) {
                str = new String(bytes);
            } else {
                str = any.toString();
            }

            printIgnoreSome(prefix, str, trim == 0);
            return;
        }

        for (int i = 0; i < array.length; i++) {
            var item = array[i];
            if (item instanceof Object[] subArray) {
                printAnyWithSpacePrefix(null, subArray, trim + 2);
            } else {
                if (i == 0) {
                    System.out.print(prefix);
                    System.out.println("-");
                }

                System.out.print(prefix + "  ");
                if (item instanceof byte[] bytes) {
                    System.out.println(new String(bytes));
                } else {
                    System.out.println(item);
                }
            }
        }
    }

    private final Logger log = LoggerFactory.getLogger(this.getClass());

    protected void handleRecord(byte[] data, boolean isRequest, long timestamp) {
        if (offsetFromTimeMillis != -1 && timestamp < offsetFromTimeMillis) {
            offsetSkippedCount++;

            if (offsetSkippedCount % 10000 == 0) {
                System.out.println("Skipped " + offsetSkippedCount + " messages with timestamp before " + offsetFromTime);
            }
            return;
        }

        var buf = Unpooled.wrappedBuffer(data);
        var cmdArgs = resp.decode(buf, isRequest, timestamp, this::printAny);
        while (cmdArgs != null) {
            validRespDataCount++;

            if (cmdArgs == RESP.RESPONSE_CMD) {
                clientReceivedCount++;
            } else {
                var cmd = cmdArgs.cmd();
                var count = countByCmd.getOrDefault(cmd, 0L);
                countByCmd.put(cmd, count + 1);
                if (Category.isReadCmd(cmd)) {
                    readCmdCount++;
                } else if (Category.isWriteCmd(cmd)) {
                    writeCmdCount++;
                } else {
                    otherCmdCount++;
                }

                printCmdArgs(cmdArgs);
            }

            cmdArgs = resp.decode(buf, isRequest, timestamp, this::printAny);
        }

        if (validRespDataCount % 10_000 == 0) {
            log.info("valid resp data count: {}, read category: {}, write category: {}",
                    validRespDataCount, readCmdCount, writeCmdCount);
        }
    }

    public void printStats() {
        System.out.println("skipped print OK result count: " + okCount);
        System.out.println("skipped print NULL result count: " + nullCount);

        // resp data count
        var row2 = MonitorAndReplay.toRow(validRespDataCount, clientReceivedCount,
                readCmdCount, writeCmdCount, otherCmdCount);
        var rows2 = new ArrayList<List<String>>();
        rows2.add(row2);

        var headers2 = MonitorAndReplay.toHeaders("valid resp data count", "client received count",
                "read cmd count", "write cmd count", "other cmd count");
        new TablePrinter(headers2).print(rows2);

        // cmd count
        MonitorAndReplay.printCmdCountStats(countByCmd);
    }

    abstract boolean connect();

    abstract void close();

    abstract void consume(int num) throws IOException;
}
