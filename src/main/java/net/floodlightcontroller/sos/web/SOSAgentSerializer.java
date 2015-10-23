package net.floodlightcontroller.sos.web;

import java.io.IOException;
import java.util.UUID;

import net.floodlightcontroller.sos.ISOSAgent;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonGenerator.Feature;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

public class SOSAgentSerializer extends JsonSerializer<ISOSAgent> {

	@Override
	public void serialize(ISOSAgent agent, JsonGenerator jGen, SerializerProvider sProv) 
			throws IOException, JsonProcessingException {
		jGen.configure(Feature.WRITE_NUMBERS_AS_STRINGS, true);

		if (agent == null) {
			jGen.writeStartArray();
			jGen.writeString("No SOS agent to report");
			jGen.writeEndArray();
			return;
		}

		jGen.writeStartObject();
		jGen.writeStringField("ip-address", agent.getIPAddr().toString());
		jGen.writeStringField("mac-address", agent.getMACAddr().toString());
		jGen.writeStringField("control-port", agent.getControlPort().toString());
		jGen.writeStringField("data-port", agent.getDataPort().toString());
		jGen.writeStringField("feedback-port", agent.getFeedbackPort().toString());
		jGen.writeArrayFieldStart("active-transfers");
		for (UUID u : agent.getActiveTransfers()) {
			jGen.writeString(u.toString());
		}
		jGen.writeEndArray();
		jGen.writeEndObject();
	}
}