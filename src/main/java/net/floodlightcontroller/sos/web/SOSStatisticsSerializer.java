package net.floodlightcontroller.sos.web;

import java.io.IOException;

import net.floodlightcontroller.sos.ISOSAgent;
import net.floodlightcontroller.sos.ISOSConnection;
import net.floodlightcontroller.sos.ISOSStatistics;
import net.floodlightcontroller.sos.ISOSWhitelistEntry;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonGenerator.Feature;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

public class SOSStatisticsSerializer extends JsonSerializer<ISOSStatistics> {
	@Override
	public void serialize(ISOSStatistics stats, JsonGenerator jGen, SerializerProvider sProv) 
			throws IOException, JsonProcessingException {
		jGen.configure(Feature.WRITE_NUMBERS_AS_STRINGS, true);

		if (stats == null) {
			jGen.writeStartObject();
			jGen.writeString("No SOS statistics to report");
			jGen.writeEndObject();
			return;
		}

		jGen.writeStartObject();
		
		jGen.writeArrayFieldStart("agents");
		for (ISOSAgent a : stats.getAgents()) {
			jGen.writeObject(a);
		}
		jGen.writeEndArray();
		
		jGen.writeArrayFieldStart("active-connections");
		for (ISOSConnection c : stats.getActiveConnections()) {
			jGen.writeObject(c);
		}
		jGen.writeEndArray();
		
		jGen.writeArrayFieldStart("terminated-connections");
		for (ISOSConnection t : stats.getTerminatedConnections()) {
			jGen.writeObject(t);
		}
		jGen.writeEndArray();
		
		jGen.writeArrayFieldStart("whitelist-entries");
		for (ISOSWhitelistEntry e : stats.getWhitelistEntries()) {
			jGen.writeObject(e);
		}
		jGen.writeEndArray();

		jGen.writeEndObject();
	}
}