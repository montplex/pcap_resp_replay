package com.montplex.resp;

import redis.clients.jedis.commands.ProtocolCommand;

public record ExtendCommand(String cmd) implements ProtocolCommand {
    @Override
    public byte[] getRaw() {
        return cmd.getBytes();
    }
}
