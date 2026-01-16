package com.montplex.resp;

import io.netty.buffer.ByteBuf;
import io.netty.util.ByteProcessor;
import io.netty.util.CharsetUtil;

// reuse decode by netty ByteBuf, copy from camellia-redis-proxy com.netease.nim.camellia.redis.proxy.netty.CommandDecoder
public class RESP {
    private static final byte STRING_MARKER = '+';
    private static final byte ERROR_MARKER = '-';
    private static final byte INTEGER_MARKER = ':';
    private static final byte BYTES_MARKER = '$';
    private static final byte ARRAY_MARKER = '*';
    private static final byte BOOLEAN_MARKER = '#';
    private static final byte NULL_MARKER = '_';
    private static final byte DOUBLE_MARKER = ',';
    private static final byte MAP_MARKER = '%';
    private static final byte SET_MARKER = '~';

    private static final int POSITIVE_LONG_MAX_LENGTH = 19; // length of Long.MAX_VALUE
    private static final int EOL_LENGTH = 2;

    private static final class NumberProcessor implements ByteProcessor {
        private int result;

        @Override
        public boolean process(byte value) {
            if (value < '0' || value > '9') {
                throw new IllegalArgumentException("Bad byte in number=" + value);
            }
            result = result * 10 + (value - '0');
            return true;
        }

        public int content() {
            return result;
        }

        public void reset() {
            result = 0;
        }
    }

    private final NumberProcessor numberProcessor = new NumberProcessor();

    private int parseRedisNumber(ByteBuf in) {
        final int readableBytes = in.readableBytes();
        final boolean negative = readableBytes > 0 && in.getByte(in.readerIndex()) == '-';
        final int extraOneByteForNegative = negative ? 1 : 0;
        if (readableBytes <= extraOneByteForNegative) {
            throw new IllegalArgumentException("No number to parse=" + in.toString(CharsetUtil.US_ASCII));
        }
        if (readableBytes > POSITIVE_LONG_MAX_LENGTH + extraOneByteForNegative) {
            throw new IllegalArgumentException("Too many characters to be a valid RESP Integer=" +
                    in.toString(CharsetUtil.US_ASCII));
        }
        if (negative) {
            numberProcessor.reset();
            in.skipBytes(extraOneByteForNegative);
            in.forEachByte(numberProcessor);
            return -1 * numberProcessor.content();
        }
        numberProcessor.reset();
        in.forEachByte(numberProcessor);
        return numberProcessor.content();
    }

    private ByteBuf readLine(ByteBuf in) {
        if (!in.isReadable(EOL_LENGTH)) {
            return null;
        }
        final int lfIndex = in.forEachByte(ByteProcessor.FIND_LF);
        if (lfIndex < 0) {
            return null;
        }
        var data = in.readSlice(lfIndex - in.readerIndex() - 1); // `-1` is for CR
        in.skipBytes(2);
        return data;
    }

    long invalidDecodeCount = 0L;

    public interface ClientDataCallback {
        void onData(long millis, Object one, Object[] array);
    }

    public static CmdArgs RESPONSE_CMD = new CmdArgs(null, null);

    public CmdArgs decode(ByteBuf bb, ClientDataCallback callback) {
        return decode(bb, false, 0, callback);
    }

    public CmdArgs decode(ByteBuf bb, boolean isRequest) {
        return decode(bb, isRequest, 0, null);
    }

    public CmdArgs decode(ByteBuf bb, boolean isRequest, long millis, ClientDataCallback callback) {
        int beforeReadIndex = bb.readerIndex();
        byte[][] bytes = null;
        outerLoop:
        while (true) {
            if (bytes == null) {
                if (bb.readableBytes() <= 0) {
                    break;
                }
                int readerIndex = bb.readerIndex();
                byte b = bb.readByte();
                if (b == ARRAY_MARKER) {
                    var lineBuf = readLine(bb);
                    if (lineBuf == null) {
                        bb.readerIndex(readerIndex);
                        break;
                    }
                    int number = parseRedisNumber(lineBuf);
                    bytes = new byte[number][];
                } else if (b == INTEGER_MARKER || b == BOOLEAN_MARKER || b == DOUBLE_MARKER
                        || b == ERROR_MARKER || b == NULL_MARKER || b == STRING_MARKER || b == BYTES_MARKER
                        || b == MAP_MARKER || b == SET_MARKER) {
                    bb.readerIndex(readerIndex);
                    var any = decodeAny(bb);
                    if (callback != null) {
                        if (any instanceof Object[] array) {
                            callback.onData(millis, null, array);
                        } else {
                            callback.onData(millis, any, null);
                        }
                    }
                    return RESPONSE_CMD;
                } else {
                    throw new IllegalArgumentException("Unexpected character=" + b);
                }
            } else {
                int numArgs = bytes.length;
                for (int i = 0; i < numArgs; i++) {
                    if (bb.readableBytes() <= 0) {
                        break outerLoop;
                    }
                    int readerIndex = bb.readerIndex();
                    byte b = bb.readByte();
                    // nested array.
                    if (b == ARRAY_MARKER) {
                        bb.readerIndex(beforeReadIndex);
                        var array = decodeArray(bb);
                        if (callback != null) {
                            callback.onData(millis, null, array);
                        }
                        return RESPONSE_CMD;
                    }

                    if (b == BYTES_MARKER) {
                        var lineBuf = readLine(bb);
                        if (lineBuf == null) {
                            bb.readerIndex(readerIndex);
                            break outerLoop;
                        }
                        int size = parseRedisNumber(lineBuf);
                        if (size == -1) { // Null bulk string
                            bytes[i] = null;
                            continue;
                        }
                        if (bb.readableBytes() >= size + 2) {
                            bytes[i] = new byte[size];
                            bb.readBytes(bytes[i]);
                            bb.skipBytes(2);
                        } else {
                            bb.readerIndex(readerIndex);
                            break outerLoop;
                        }
                    } else {
                        throw new IllegalArgumentException("Unexpected character： " + b);
                    }
                }
                break;
            }
        }

        if (bytes == null || bytes.length == 0) {
            return null;
        }
        for (var b : bytes) {
            if (b == null) {
                invalidDecodeCount++;
                return null;
            }
        }

        if (!isRequest) {
            if (callback != null) {
                callback.onData(millis, null, bytes);
            }
            return RESPONSE_CMD;
        }

        // Convert the first byte array to command string (the command itself)
        var cmd = new String(bytes[0]).toUpperCase();

        // Convert remaining byte arrays to argument strings
        var args = new byte[bytes.length - 1][];
        System.arraycopy(bytes, 1, args, 0, bytes.length - 1);

        return new CmdArgs(cmd, args);
    }

    // New method to decode any RESP type (not just commands)
    public Object decodeAny(ByteBuf bb) {
        if (!bb.isReadable()) {
            return null;
        }

        int readerIndex = bb.readerIndex();
        byte b = bb.getByte(readerIndex);

        return switch (b) {
            case STRING_MARKER -> decodeSimpleString(bb);
            case ERROR_MARKER -> decodeError(bb);
            case INTEGER_MARKER -> decodeInteger(bb);
            case BYTES_MARKER -> decodeBulkString(bb);
            case ARRAY_MARKER -> decodeArray(bb);
            case BOOLEAN_MARKER -> decodeBoolean(bb);
            case NULL_MARKER -> decodeNull(bb);
            case DOUBLE_MARKER -> decodeDouble(bb);
            case MAP_MARKER -> decodeMap(bb);
            case SET_MARKER -> decodeSet(bb);
            default -> throw new IllegalArgumentException("Unknown RESP type: " + (char) b);
        };
    }

    private String decodeSimpleString(ByteBuf bb) {
        bb.readByte(); // skip marker
        var line = readLine(bb);
        if (line != null) {
            return line.toString(CharsetUtil.UTF_8);
        }
        return null;
    }

    private String decodeError(ByteBuf bb) {
        bb.readByte(); // skip marker
        var line = readLine(bb);
        if (line != null) {
            return line.toString(CharsetUtil.UTF_8);
        }
        return null;
    }

    private Long decodeInteger(ByteBuf bb) {
        bb.readByte(); // skip marker
        var line = readLine(bb);
        if (line != null) {
            return (long) parseRedisNumber(line);
        }
        return null;
    }

    private byte[] decodeBulkString(ByteBuf bb) {
        bb.readByte(); // skip marker
        var line = readLine(bb);
        if (line != null) {
            int size = parseRedisNumber(line);
            if (size == -1) { // null bulk string
                return "null".getBytes();
            }
            if (bb.readableBytes() >= size + 2) { // +2 for \r\n
                var data = new byte[size];
                bb.readBytes(data);
                bb.skipBytes(2); // skip \r\n
                return data;
            }
        }
        return null;
    }

    private Object[] decodeArray(ByteBuf bb) {
        bb.readByte(); // skip marker
        var line = readLine(bb);
        if (line != null) {
            int size = parseRedisNumber(line);
            if (size == -1) { // null array
                return null;
            }

            var array = new Object[size];
            for (int i = 0; i < size; i++) {
                array[i] = decodeAny(bb);
            }
            return array;
        }
        return null;
    }

    private Boolean decodeBoolean(ByteBuf bb) {
        bb.readByte(); // skip marker
        var line = readLine(bb);
        if (line != null) {
            var value = line.toString(CharsetUtil.UTF_8);
            if ("t".equals(value)) {
                return true;
            } else if ("f".equals(value)) {
                return false;
            }
        }
        return null;
    }

    private Object decodeNull(ByteBuf bb) {
        bb.readByte(); // skip marker
        var line = readLine(bb);
        // Should be followed by \r\n indicating null
        return "null";
    }

    private Double decodeDouble(ByteBuf bb) {
        bb.readByte(); // skip marker
        var line = readLine(bb);
        if (line != null) {
            var value = line.toString(CharsetUtil.UTF_8);
            return Double.parseDouble(value);
        }
        return null;
    }

    private Object decodeMap(ByteBuf bb) {
        bb.readByte(); // skip marker
        var line = readLine(bb);
        if (line != null) {
            int size = parseRedisNumber(line);
            // For simplicity, returning as array alternating key/value pairs
            var map = new Object[size * 2];
            for (int i = 0; i < size * 2; i++) {
                map[i] = decodeAny(bb);
            }
            return map;
        }
        return null;
    }

    private Object[] decodeSet(ByteBuf bb) {
        bb.readByte(); // skip marker
        var line = readLine(bb);
        if (line != null) {
            int size = parseRedisNumber(line);
            var set = new Object[size];
            for (int i = 0; i < size; i++) {
                set[i] = decodeAny(bb);
            }
            return set;
        }
        return null;
    }
}