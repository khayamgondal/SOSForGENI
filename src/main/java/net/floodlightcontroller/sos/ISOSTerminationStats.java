package net.floodlightcontroller.sos;

import java.util.UUID;

import net.floodlightcontroller.sos.web.SOSTerminationStatsSerializer;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@JsonSerialize(using=SOSTerminationStatsSerializer.class)
public interface ISOSTerminationStats {
	public static final String STR_KEY_TRANSFER_ID = "transfer_id";
	public static final String STR_KEY_OVERHEAD = "overhead";
	public static final String STR_KEY_SENT_BYTES_AVG = "avg_sent_bytes";
	public static final String STR_KEY_SENT_BYTES_STD = "std_sent_bytes";
	public static final String STR_KEY_CHUNKS_AVG = "avg_chunks";
	public static final String STR_KEY_CHUNKS_STD = "std_chunks";
	public static final String STR_KEY_TYPE = "type";
	public static final String STR_VALUE_TYPE_CLIENT = "client";

	
	public UUID getTransferID();
	
	public int getOverhead();
	
	public int getSentBytesAvg();
	
	public int getSentBytesStd();
	
	public int getChunksAvg();
	
	public int getChunksStd();
	
	public boolean isClientSideAgent();
}
