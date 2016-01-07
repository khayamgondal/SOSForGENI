package net.floodlightcontroller.sos;

import java.util.Map;
import java.util.UUID;

import org.projectfloodlight.openflow.types.U64;

import net.floodlightcontroller.sos.web.SOSTransferStatsSerializer;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@JsonSerialize(using=SOSTransferStatsSerializer.class)
public interface ISOSTransferStats {
	public static final String STR_KEY_TRANSFER_ID = "transfer_id";
	public static final String STR_KEY_CUMULATIVE_THROUGHPUT = "cumulative_throughput";
	public static final String STR_KEY_ROLLING_THROUGHPUT = "rolling_throughput";
	public static final String STR_VALUE_TYPE_CLIENT = "client";
	public static final String STR_KEY_TYPE = "agent_type";
	public static final String STR_KEY_COLLECTION_TIME = "collection_time";
	public static final String STR_KEY_PER_SOCKET_THROUGHPUT = "per_socket_throughput";
	public static final String STR_KEY_SOCKET_ID = "socket_id";
		
	public U64 getAggregateCumulativeThroughput();
	
	public U64 getAggregateRollingThroughput();
	
	public U64 getCumulativeThroughput(int socket);
	
	public U64 getRollingThroughput(int socket);
	
	public UUID getTransferID();
	
	public Map<Integer, ThroughputTuple> getAllSocketsThroughput();
	
	public long getCollectionTime();
	
	public boolean isClientSideAgent();
}

