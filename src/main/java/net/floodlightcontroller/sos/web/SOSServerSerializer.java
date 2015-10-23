package net.floodlightcontroller.sos.web;

import java.io.IOException;

import net.floodlightcontroller.sos.ISOSServer;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonGenerator.Feature;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;

public class SOSServerSerializer extends JsonSerializer<ISOSServer> {
	
	@Override
	public void serialize(ISOSServer server, JsonGenerator jGen, SerializerProvider sProv) 
			throws IOException, JsonProcessingException {
		jGen.configure(Feature.WRITE_NUMBERS_AS_STRINGS, true);

		if (server == null) {
			jGen.writeStartArray();
			jGen.writeString("No SOS server to report");
			jGen.writeEndArray();
			return;
		}

		jGen.writeStartObject();
		jGen.writeStringField("ip-address", server.getIPAddr().toString());
		jGen.writeStringField("mac-address", server.getMACAddr().toString());
		jGen.writeStringField("tcp-port", server.getTcpPort().toString());
		jGen.writeEndObject();
	}
}