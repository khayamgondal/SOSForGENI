package net.floodlightcontroller.sos.web;

import java.io.IOException;

import net.floodlightcontroller.sos.ISOSTransferStats;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonGenerator.Feature;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

public class SOSTransferStatsSerializer extends JsonSerializer<ISOSTransferStats> {

	@Override
	public void serialize(ISOSTransferStats stats, JsonGenerator jGen, SerializerProvider sProv) 
			throws IOException, JsonProcessingException {
		jGen.configure(Feature.WRITE_NUMBERS_AS_STRINGS, true);

		if (stats == null) {
			jGen.writeStartArray();
			jGen.writeString("No SOS termination stats to report");
			jGen.writeEndArray();
			return;
		}

		jGen.writeStartObject();
		jGen.writeNumberField(ISOSTransferStats.STR_KEY_COLLECTION_TIME, stats.getCollectionTime());
		jGen.writeNumberField(ISOSTransferStats.STR_KEY_CUMULATIVE_THROUGHPUT, stats.getAggregateCumulativeThroughput().getValue());
		jGen.writeNumberField(ISOSTransferStats.STR_KEY_ROLLING_THROUGHPUT, stats.getAggregateRollingThroughput().getValue());
		jGen.writeStringField(ISOSTransferStats.STR_KEY_TRANSFER_ID, stats.getTransferID().toString());
		jGen.writeStringField(ISOSTransferStats.STR_KEY_TYPE, stats.isClientSideAgent() ? "client-side-agent" : "server-side-agent");
		jGen.writeArrayFieldStart(ISOSTransferStats.STR_KEY_PER_SOCKET_THROUGHPUT);
		for (int id : stats.getAllSocketsThroughput().keySet()) {
			jGen.writeStartObject();
			jGen.writeNumberField(ISOSTransferStats.STR_KEY_SOCKET_ID, id);
			jGen.writeNumberField(ISOSTransferStats.STR_KEY_CUMULATIVE_THROUGHPUT, stats.getAllSocketsThroughput().get(id).getCumulativeThroughput().getValue());
			jGen.writeNumberField(ISOSTransferStats.STR_KEY_ROLLING_THROUGHPUT, stats.getAllSocketsThroughput().get(id).getRollingThroughput().getValue());
			jGen.writeEndObject();
		}
		jGen.writeEndArray();
		jGen.writeEndObject();
	}
}