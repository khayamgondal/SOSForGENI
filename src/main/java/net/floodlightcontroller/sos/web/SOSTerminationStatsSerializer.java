package net.floodlightcontroller.sos.web;

import java.io.IOException;

import net.floodlightcontroller.sos.ISOSTerminationStats;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonGenerator.Feature;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

public class SOSTerminationStatsSerializer extends JsonSerializer<ISOSTerminationStats> {

	@Override
	public void serialize(ISOSTerminationStats stats, JsonGenerator jGen, SerializerProvider sProv) 
			throws IOException, JsonProcessingException {
		jGen.configure(Feature.WRITE_NUMBERS_AS_STRINGS, true);

		if (stats == null) {
			jGen.writeStartArray();
			jGen.writeString("No SOS termination stats to report");
			jGen.writeEndArray();
			return;
		}

		jGen.writeStartObject();
		jGen.writeNumberField(ISOSTerminationStats.STR_KEY_CHUNKS_AVG, stats.getChunksAvg());
		jGen.writeNumberField(ISOSTerminationStats.STR_KEY_CHUNKS_STD, stats.getChunksStd());
		jGen.writeNumberField(ISOSTerminationStats.STR_KEY_OVERHEAD, stats.getOverhead());
		jGen.writeNumberField(ISOSTerminationStats.STR_KEY_SENT_BYTES_AVG, stats.getSentBytesAvg());
		jGen.writeNumberField(ISOSTerminationStats.STR_KEY_SENT_BYTES_STD, stats.getSentBytesStd());
		/* do not include transfer ID */
		jGen.writeEndObject();
	}
}